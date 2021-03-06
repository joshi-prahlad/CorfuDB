package org.corfudb.runtime;

import com.codahale.metrics.MetricRegistry;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import lombok.Data;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

import org.corfudb.protocols.wireprotocol.VersionInfo;
import org.corfudb.recovery.FastObjectLoader;
import org.corfudb.runtime.clients.BaseClient;
import org.corfudb.runtime.clients.IClientRouter;
import org.corfudb.runtime.clients.LayoutClient;
import org.corfudb.runtime.clients.LogUnitClient;
import org.corfudb.runtime.clients.ManagementClient;
import org.corfudb.runtime.clients.NettyClientRouter;
import org.corfudb.runtime.clients.SequencerClient;
import org.corfudb.runtime.exceptions.NetworkException;
import org.corfudb.runtime.view.AddressSpaceView;
import org.corfudb.runtime.view.Layout;
import org.corfudb.runtime.view.LayoutView;
import org.corfudb.runtime.view.ObjectsView;
import org.corfudb.runtime.view.SequencerView;
import org.corfudb.runtime.view.StreamsView;
import org.corfudb.util.GitRepositoryState;
import org.corfudb.util.MetricsUtils;
import org.corfudb.util.Version;

/**
 * Created by mwei on 12/9/15.
 */
@Slf4j
@Accessors(chain = true)
public class CorfuRuntime {

    static final int DEFAULT_TIMEOUT_MINUTES_FAST_LOADING = 30;

    public static final int BULK_READ_SIZE = 10;

    @Data
    public static class CorfuRuntimeParameters {

        /** True, if undo logging is disabled. */
        boolean undoDisabled = false;

        /** True, if optimistic undo logging is disabled. */
        boolean optimisticUndoDisabled = false;

        /** Number of times to attempt to read before hole filling. */
        int holeFillRetry = 10;
    }

    @Getter
    private final CorfuRuntimeParameters parameters = new CorfuRuntimeParameters();
    /**
     * A view of the layout service in the Corfu server instance.
     */
    @Getter(lazy = true)
    private final LayoutView layoutView = new LayoutView(this);
    /**
     * A view of the sequencer server in the Corfu server instance.
     */
    @Getter(lazy = true)
    private final SequencerView sequencerView = new SequencerView(this);
    /**
     * A view of the address space in the Corfu server instance.
     */
    @Getter(lazy = true)
    private final AddressSpaceView addressSpaceView = new AddressSpaceView(this);
    /**
     * A view of streamsView in the Corfu server instance.
     */
    @Getter(lazy = true)
    private final StreamsView streamsView = new StreamsView(this);

    //region Address Space Options
    /**
     * Views of objects in the Corfu server instance.
     */
    @Getter(lazy = true)
    private final ObjectsView objectsView = new ObjectsView(this);
    /**
     * A list of known layout servers.
     */
    private List<String> layoutServers;

    //endregion Address Space Options
    /**
     * A map of routers, representing nodes.
     */
    public Map<String, IClientRouter> nodeRouters;
    /**
     * A completable future containing a layout, when completed.
     */
    public volatile CompletableFuture<Layout> layout;
    /**
     * The rate in seconds to retry accessing a layout, in case of a failure.
     */
    public int retryRate;
    /**
     * Whether or not to disable the cache.
     */
    @Getter
    public boolean cacheDisabled = false;
    /**
     * The maximum size of the cache, in bytes.
     */
    @Getter
    @Setter
    public long numCacheEntries = 5000;

    /**
     * The number of times to retry on a retriable TrimException within during a transaction
     */
    @Getter
    @Setter
    public int trimRetry = 2;

    /**
     * Number of times to retry on an OverwriteException before giving up.
     */
    @Getter
    @Setter
    public int writeRetry = 3;

    /**
     * Sets expireAfterAccess and expireAfterWrite in seconds.
     */
    @Getter
    @Setter
    public long cacheExpiryTime = Long.MAX_VALUE;

    /**
     * Whether or not to disable backpointers.
     */
    @Getter
    public boolean backpointersDisabled = false;

    /**
     * If hole filling is disabled.
     */
    @Getter
    @Setter
    public boolean holeFillingDisabled = false;

    /**
     * Notifies that the runtime is no longer used
     * and async retries to fetch the layout can be stopped.
     */
    @Getter
    private volatile boolean isShutdown = false;

    private boolean tlsEnabled = false;
    private String keyStore;
    private String ksPasswordFile;
    private String trustStore;
    private String tsPasswordFile;

    private boolean saslPlainTextEnabled = false;
    private String usernameFile;
    private String passwordFile;


    /**
     * Trigger the loading of all the SmrMaps upon connect.
     *
     * <p>If using this utility, you need to be sure that no one
     * is acessing objects until the tables are loaded
     * (i.e. when connect return)</p>
     */
    @Setter
    @Getter
    private boolean loadSmrMapsAtConnect = false;


    /**
     * Set the bulk read size.
     */
    @Setter
    @Getter
    public int bulkReadSize = BULK_READ_SIZE;


    /**
     * How much time the Fast Loader has to get the maps up to date.
     *
     * <p>Once the timeout is reached, the Fast Loader give up. Every maps that are
     * not up to date will be loaded through normal path.</p>
     *
     */
    @Getter
    @Setter
    private int timeoutInMinutesForFastLoading = DEFAULT_TIMEOUT_MINUTES_FAST_LOADING;

    /**
     * Metrics: meter (counter), histogram.
     */
    private static final String mp = "corfu.runtime.";
    @Getter
    private static final String mpASV = mp + "as-view.";
    @Getter
    private static final String mpLUC = mp + "log-unit-client.";
    @Getter
    private static final String mpCR = mp + "client-router.";
    @Getter
    private static final String mpObj = mp + "object.";
    @Getter
    private static MetricRegistry defaultMetrics = new MetricRegistry();
    @Getter
    private MetricRegistry metrics = new MetricRegistry();

    public CorfuRuntime setMetrics(@NonNull MetricRegistry metrics) {
        this.metrics = metrics;
        return this;
    }

    /**
     * When set, overrides the default getRouterFunction. Used by the testing
     * framework to ensure the default routers used are for testing.
     */
    public static BiFunction<CorfuRuntime, String, IClientRouter> overrideGetRouterFunction = null;

    /**
     * A function to handle getting routers. Used by test framework to inject
     * a test router. Can also be used to provide alternative logic for obtaining
     * a router.
     */
    @Getter
    @Setter
    public Function<String, IClientRouter> getRouterFunction = overrideGetRouterFunction != null
            ? (address) -> overrideGetRouterFunction.apply(this, address) : (address) -> {

                // Return an existing router if we already have one.
                if (nodeRouters.containsKey(address)) {
                    return nodeRouters.get(address);
                }
                // Parse the string in host:port format.
                String host = address.split(":")[0];
                Integer port = Integer.parseInt(address.split(":")[1]);
                // Generate a new router, start it and add it to the table.
                NettyClientRouter router = new NettyClientRouter(host, port,
                        tlsEnabled, keyStore, ksPasswordFile, trustStore, tsPasswordFile,
                        saslPlainTextEnabled, usernameFile, passwordFile);
                log.debug("Connecting to new router {}:{}", host, port);
                try {
                    router.addClient(new LayoutClient())
                            .addClient(new SequencerClient())
                            .addClient(new LogUnitClient().setMetricRegistry(metrics != null
                                            ? metrics : CorfuRuntime.getDefaultMetrics()))
                            .addClient(new ManagementClient())
                            .start();
                    nodeRouters.put(address, router);
                } catch (Exception e) {
                    log.warn("Error connecting to router", e);
                }
                return router;
            };

    /**
     * Constructor for CorfuRuntime.
     **/
    public CorfuRuntime() {
        layoutServers = new ArrayList<>();
        nodeRouters = new ConcurrentHashMap<>();
        retryRate = 5;

        getAddressSpaceView().setMetrics(metrics != null
                ? metrics : CorfuRuntime.getDefaultMetrics());
        synchronized (metrics) {
            if (metrics.getNames().isEmpty()) {
//                MetricsUtils.addJvmMetrics(metrics, mp);
                MetricsUtils.metricsReportingSetup(metrics);
            }
        }
        log.info("Corfu runtime version {} initialized.", getVersionString());
    }

    /**
     * Parse a configuration string and get a CorfuRuntime.
     *
     * @param configurationString The configuration string to parse.
     */
    public CorfuRuntime(String configurationString) {
        this();
        this.parseConfigurationString(configurationString);
    }

    /**
     * Enable TLS.
     **/
    public CorfuRuntime enableTls(String keyStore, String ksPasswordFile, String trustStore,
                                  String tsPasswordFile) {
        this.keyStore = keyStore;
        this.ksPasswordFile = ksPasswordFile;
        this.trustStore = trustStore;
        this.tsPasswordFile = tsPasswordFile;
        this.tlsEnabled = true;
        return this;
    }

    /**
     * Enable SASL Plain Text.
     **/
    public CorfuRuntime enableSaslPlainText(String usernameFile, String passwordFile) {
        this.usernameFile = usernameFile;
        this.passwordFile = passwordFile;
        this.saslPlainTextEnabled = true;
        return this;
    }

    /**
     * Shuts down the CorfuRuntime.
     * Stops async tasks from fetching the layout.
     * Cannot reuse the runtime once shutdown is called.
     */
    public void shutdown() {

        // Stopping async task from fetching layout.
        isShutdown = true;
        if (layout != null) {
            try {
                layout.cancel(true);
            } catch (Exception e) {
                log.error("Runtime shutting down. Exception in terminating fetchLayout: {}", e);
            }
        }
        stop(true);
    }

    /**
     * Stop all routers associated with this runtime & disconnect them.
     */
    public void stop() {
        stop(false);
    }

    /**
     * Stop all routers associated with this Corfu Runtime.
     **/
    public void stop(boolean shutdown) {
        for (IClientRouter r: nodeRouters.values()) {
            r.stop(shutdown);
        }
        if (!shutdown) {
            // N.B. An icky side-effect of this clobbering is leaking
            // Pthreads, namely the Netty client-side worker threads.
            nodeRouters = new ConcurrentHashMap<>();
        }
    }

    /**
     * Get a UUID for a named stream.
     *
     * @param string The name of the stream.
     * @return The ID of the stream.
     */
    @SuppressWarnings("checkstyle:abbreviation")
    public static UUID getStreamID(String string) {
        return UUID.nameUUIDFromBytes(string.getBytes());
    }

    public static UUID getCheckpointStreamIdFromId(UUID streamId) {
        return getStreamID(streamId.toString() + StreamsView.CHECKPOINT_SUFFIX);
    }

    public static UUID getCheckpointStreamIdFromName(String streamName) {
        return getCheckpointStreamIdFromId(CorfuRuntime.getStreamID(streamName));
    }

    /**
     * Get corfy runtime version.
     **/
    public static String getVersionString() {
        if (Version.getVersionString().contains("SNAPSHOT")
                || Version.getVersionString().contains("source")) {
            return Version.getVersionString() + "("
                    + GitRepositoryState.getRepositoryState().commitIdAbbrev + ")";
        }
        return Version.getVersionString();
    }

    /**
     * Whether or not to disable backpointers
     *
     * @param disable True, if the cache should be disabled, false otherwise.
     * @return A CorfuRuntime to support chaining.
     */
    public CorfuRuntime setBackpointersDisabled(boolean disable) {
        this.backpointersDisabled = disable;
        return this;
    }

    /**
     * Whether or not to disable the cache
     *
     * @param disable True, if the cache should be disabled, false otherwise.
     * @return A CorfuRuntime to support chaining.
     */
    public CorfuRuntime setCacheDisabled(boolean disable) {
        this.cacheDisabled = disable;
        return this;
    }

    /**
     * If enabled, successful transactions will be written to a special transaction stream
     * (i.e. TRANSACTION_STREAM_ID)
     * @param enable indicates if transaction logging is enabled
     * @return corfu runtime object
     */
    public CorfuRuntime setTransactionLogging(boolean enable) {
        this.getObjectsView().setTransactionLogging(enable);
        return this;
    }

    /**
     * Parse a configuration string and get a CorfuRuntime.
     *
     * @param configurationString The configuration string to parse.
     * @return A CorfuRuntime Configured based on the configuration string.
     */
    public CorfuRuntime parseConfigurationString(String configurationString) {
        // Parse comma sep. list.
        layoutServers = Pattern.compile(",")
                .splitAsStream(configurationString)
                .map(String::trim)
                .collect(Collectors.toList());
        return this;
    }

    /**
     * Add a layout server to the list of servers known by the CorfuRuntime.
     *
     * @param layoutServer A layout server to use.
     * @return A CorfuRuntime, to support the builder pattern.
     */
    public CorfuRuntime addLayoutServer(String layoutServer) {
        layoutServers.add(layoutServer);
        return this;
    }

    /**
     * Get a router, given the address.
     *
     * @param address The address of the router to get.
     * @return The router.
     */
    public IClientRouter getRouter(String address) {
        return getRouterFunction.apply(address);
    }

    /**
     * Invalidate the current layout.
     * If the layout has been previously invalidated and a new layout has not yet been retrieved,
     * this function does nothing.
     */
    public synchronized void invalidateLayout() {
        // Is there a pending request to retrieve the layout?
        if (!layout.isDone()) {
            // Don't create a new request for a layout if there is one pending.
            return;
        }
        layout = fetchLayout();
    }


    /**
     * Return a completable future which is guaranteed to contain a layout.
     * This future will continue retrying until it gets a layout.
     * If you need this completable future to fail, you should chain it with a timeout.
     *
     * @return A completable future containing a layout.
     */
    private CompletableFuture<Layout> fetchLayout() {
        return CompletableFuture.<Layout>supplyAsync(() -> {

            while (true) {
                List<String> layoutServersCopy =  layoutServers.stream().collect(
                        Collectors.toList());
                Collections.shuffle(layoutServersCopy);
                // Iterate through the layout servers, attempting to connect to one
                for (String s : layoutServersCopy) {
                    log.debug("Trying connection to layout server {}", s);
                    try {
                        IClientRouter router = getRouter(s);
                        // Try to get a layout.
                        CompletableFuture<Layout> layoutFuture = router
                                .getClient(LayoutClient.class).getLayout();
                        // Wait for layout
                        Layout l = layoutFuture.get();

                        // If the layout we got has a smaller epoch than the router,
                        // we discard it.
                        if (l.getEpoch() < router.getEpoch()) {
                            log.warn("fetchLayout: Received a layout with epoch {} from server "
                                            + "{}:{} smaller than router epoch {}, discarded.",
                                    l.getEpoch(), router.getHost(),
                                    router.getPort(), router.getEpoch());
                            continue;
                        }

                        l.setRuntime(this);
                        // this.layout should only be assigned to the new layout future
                        // once it has been completely constructed and initialized.
                        // For example, assigning this.layout = l
                        // before setting the layout's runtime can result in other threads
                        // trying to access a layout with  a null runtime.
                        // FIXME Synchronization START
                        // We are updating multiple variables and we need the update to be
                        // synchronized across all variables.
                        // Since the variable layoutServers is used only locally within the class
                        // it is acceptable (at least the code on 10/13/2016 does not have issues)
                        // but setEpoch of routers needs to be synchronized as those variables are
                        // not local.
                        try {
                            l.getAllServers().stream().map(getRouterFunction).forEach(x ->
                                    x.setEpoch(l.getEpoch()));
                        } catch (NetworkException ne) {
                            // We have already received the layout and there is no need to keep client waiting.
                            // NOTE: This is true assuming this happens only at router creation.
                            // If not we also have to take care of setting the latest epoch on Client Router.
                            log.warn("fetchLayout: Error getting router : {}", ne);
                        }
                        layoutServers = l.getLayoutServers();
                        layout = layoutFuture;
                        //FIXME Synchronization END

                        log.debug("Layout server {} responded with layout {}", s, l);
                        return l;
                    } catch (Exception e) {
                        log.warn("Tried to get layout from {} but failed with exception:", s, e);
                    }
                }
                log.warn("Couldn't connect to any up-to-date layout servers, retrying in {}s.",
                        retryRate);
                try {
                    Thread.sleep(retryRate * 1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                if (isShutdown) {
                    return null;
                }
            }
        });
    }

    @SuppressWarnings("unchecked")
    private void checkVersion() {
        try {
            CompletableFuture<VersionInfo>[] futures = layout.get().getLayoutServers()
                    .stream().map(this::getRouter)
                    .map(r -> r.getClient(BaseClient.class))
                    .map(BaseClient::getVersionInfo)
                    .toArray(CompletableFuture[]::new);

            CompletableFuture.allOf(futures).join();

            for (CompletableFuture<VersionInfo> cf : futures) {
                if (cf.get().getVersion() == null) {
                    log.error("Unexpected server version, server is too old to return"
                            + " version information");
                } else if (!cf.get().getVersion().equals(getVersionString())) {
                    log.error("connect: expected version {}, but server version is {}",
                            getVersionString(), cf.get().getVersion());
                } else {
                    log.info("connect: client version {}, server version is {}",
                            getVersionString(), cf.get().getVersion());
                }
            }
        } catch (Exception e) {
            log.error("connect: failed to get version", e);
        }
    }

    /**
     * Connect to the Corfu server instance.
     * When this function returns, the Corfu server is ready to be accessed.
     */
    public synchronized CorfuRuntime connect() {
        if (layout == null) {
            log.info("Connecting to Corfu server instance, layout servers={}", layoutServers);
            // Fetch the current layout and save the future.
            layout = fetchLayout();
            try {
                layout.get();
            } catch (Exception e) {
                // A serious error occurred trying to connect to the Corfu instance.
                log.error("Fatal error connecting to Corfu server instance.", e);
                throw new RuntimeException(e);
            }
        }

        checkVersion();

        if (loadSmrMapsAtConnect) {
            FastObjectLoader fastLoader = new FastObjectLoader(this)
                    .setBatchReadSize(getBulkReadSize())
                    .setTimeoutInMinutesForLoading(timeoutInMinutesForFastLoading);
            fastLoader.loadMaps();
        }
        return this;
    }
}
