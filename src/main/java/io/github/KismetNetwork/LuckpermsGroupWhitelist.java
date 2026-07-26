package io.github.KismetNetwork;

import com.google.inject.Inject;
import com.moandjiezana.toml.Toml;
import com.velocitypowered.api.event.PostOrder;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.event.proxy.ProxyReloadEvent;
import com.velocitypowered.api.plugin.Dependency;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.luckperms.api.LuckPermsProvider;
import net.luckperms.api.model.user.User;
import net.luckperms.api.node.NodeType;
import net.luckperms.api.node.types.InheritanceNode;
import org.slf4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

@Plugin(id = "luckpermsgroupwhitelist",
        name = "Luckperms Group Whitelist",
        version = "0.2.0",
        url = "https://github.com/emil-jacero/luckperms-group-whitelist",
        description = "Only allow a certain luckperms group to join a server ",
        authors = {"AI-nsley69", "Ampflower", "emil-jacero"},
        dependencies = {@Dependency(id = "luckperms")})
public class LuckpermsGroupWhitelist {
    // Environment variable that configures the server->groups map without a
    // config.toml file. Format: entries separated by ';' or newlines, each
    // "server=group,group,...". When set it is the source of truth (merged over
    // any config.toml), so the plugin can be configured purely through the proxy
    // container's env - no writable data dir and no config-file injection needed.
    // Example: LPGW_SERVERS="smp=fox,keeper,elder,warden;dungeons=fox,keeper,elder,warden"
    private static final String ENV_SERVERS = "LPGW_SERVERS";

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;

    private final HashMap<String, List<String>> allowedGroupLookup = new HashMap<>();

    // Initialization
    @Inject
    public LuckpermsGroupWhitelist(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) throws IOException, IllegalArgumentException {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;

        readConfig();
    }

    private void readConfig() throws IOException, IllegalArgumentException {
        HashMap<String, List<String>> buffer = new HashMap<>();

        String env = System.getenv(ENV_SERVERS);
        boolean envConfigured = env != null && !env.isBlank();

        Path config = dataDirectory.resolve("config.toml");
        if (envConfigured) {
            // Env is the source of truth. Merge an existing config.toml underneath
            // it if one happens to be present, but never create one - an env-only
            // deployment needs no writable data dir.
            if (Files.exists(config)) {
                readToml(config, buffer);
            }
        } else if (Files.notExists(config)) {
            // No env, no file: seed the bundled default so operators have something
            // to edit (unchanged upstream behaviour).
            try (InputStream input = LuckpermsGroupWhitelist.class.getResourceAsStream("/assets/lpgw/default.toml")) {
                Files.createDirectories(dataDirectory);
                Files.copy(Objects.requireNonNull(input, "Jar or class loader is bad."), config);
            }
        } else {
            readToml(config, buffer);
        }

        if (envConfigured) {
            parseServersEnv(env, buffer);
        }

        // If we made it here, the config was read successfully.
        allowedGroupLookup.clear();
        allowedGroupLookup.putAll(buffer);
        logger.info("Loaded group-whitelist for {} server(s) from {}.", buffer.size(),
                envConfigured ? ENV_SERVERS + " env" : "config.toml");
    }

    // Reads the [servers] table of a config.toml into buffer (server -> groups).
    private void readToml(Path config, Map<String, List<String>> buffer) throws IOException, IllegalArgumentException {
        try (InputStream input = Files.newInputStream(config)) {
            Toml toml = new Toml();
            toml.read(input);

            Toml servers = toml.getTable("servers");
            if (servers == null) {
                return;
            }
            for (var entry : servers.entrySet()) {
                Object entryValue = entry.getValue();
                if (entryValue instanceof Collection<?>) {
                    var values = new ArrayList<String>();

                    for (var value : (Collection<?>) entryValue) {
                        if (value instanceof String) {
                            values.add((String) value);
                        } else {
                            throw new IllegalArgumentException("Invalid entry for key " + entry.getKey() + ": " + value + "; contained within " + entryValue);
                        }
                    }

                    buffer.put(entry.getKey(), values);
                } else {
                    throw new IllegalArgumentException("Invalid object for key " + entry.getKey() + ": " + entry.getValue());
                }
            }
        }
    }

    // Parses LPGW_SERVERS ("server=g1,g2;server2=g3,...") into buffer, overriding
    // any same-named file entry. Whitespace is trimmed; blank entries/groups are
    // skipped; a malformed entry (no '=', empty server, or no groups) is fatal so
    // a typo fails loudly rather than silently disabling the gate for a server.
    private void parseServersEnv(String raw, Map<String, List<String>> buffer) throws IllegalArgumentException {
        for (String entry : raw.split("[;\n]")) {
            entry = entry.trim();
            if (entry.isEmpty()) {
                continue;
            }
            int eq = entry.indexOf('=');
            if (eq < 1) {
                throw new IllegalArgumentException("Invalid " + ENV_SERVERS + " entry (expected server=group,group): " + entry);
            }
            String serverName = entry.substring(0, eq).trim();
            List<String> groups = new ArrayList<>();
            for (String g : entry.substring(eq + 1).split(",")) {
                g = g.trim();
                if (!g.isEmpty()) {
                    groups.add(g);
                }
            }
            if (serverName.isEmpty() || groups.isEmpty()) {
                throw new IllegalArgumentException("Invalid " + ENV_SERVERS + " entry (empty server or groups): " + entry);
            }
            buffer.put(serverName, groups);
        }
    }

    @Subscribe
    public void onProxyReload(ProxyReloadEvent event) {
        try {
            readConfig();
        } catch (IOException | IllegalArgumentException exception) {
            logger.warn("Failed to reload the config, falling back to already loaded.", exception);
        }
    }

    // onServerPreConnect event to check if the player is in the group it needs to be able to connect
    @Subscribe(order = PostOrder.EARLY)
    public void onServerPreConnect(ServerPreConnectEvent event) {
        // Get the server and then the name from the server
        RegisteredServer server = event.getOriginalServer();
        String serverName = server.getServerInfo().getName();

        // Check if requiredGroups has permissions, otherwise return
        List<String> requiredGroups = allowedGroupLookup.get(serverName);
        if (requiredGroups == null || requiredGroups.isEmpty()) return;

        // Get the player object
        Player player = event.getPlayer();

        // Get the luckperms user & group
        User user = LuckPermsProvider.get().getPlayerAdapter(Player.class).getUser(player);
        Set<String> groups = user.getNodes(NodeType.INHERITANCE).stream()
                .map(InheritanceNode::getGroupName)
                .collect(Collectors.toSet());

        // Iterate over the required groups and check if the user is in said group
        for (String g : requiredGroups) {
            if (groups.contains(g)) {
                return;
            }
        }

        event.setResult(ServerPreConnectEvent.ServerResult.denied());
    }
}
