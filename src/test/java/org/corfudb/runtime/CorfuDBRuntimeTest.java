package org.corfudb.runtime;

import org.corfudb.runtime.protocols.IServerProtocol;
import org.corfudb.runtime.protocols.configmasters.IConfigMaster;
import org.corfudb.runtime.protocols.configmasters.MemoryConfigMasterProtocol;
import org.corfudb.runtime.protocols.logunits.MemoryLogUnitProtocol;
import org.corfudb.runtime.protocols.sequencers.MemorySequencerProtocol;
import org.corfudb.runtime.stream.IStream;
import org.corfudb.runtime.view.ConfigurationMaster;
import org.junit.Assert;
import org.junit.Test;
import static org.junit.Assert.assertNotNull;
import static org.assertj.core.api.Assertions.*;
import org.corfudb.runtime.view.CorfuDBView;
import org.reflections.Reflections;
import org.reflections.scanners.SubTypesScanner;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Created by mwei on 4/30/15.
 */
public class CorfuDBRuntimeTest {
    @Test
    public void MemoryCorfuDBRuntimeHasComponents() {
        CorfuDBRuntime runtime = new CorfuDBRuntime("memory");
        CorfuDBView view = runtime.getView();
        assertNotNull(view);
        assertThat(view.getConfigMasters().get(0))
                .isInstanceOf(MemoryConfigMasterProtocol.class);
        assertThat(view.getSequencers().get(0))
                .isInstanceOf(MemorySequencerProtocol.class);
        assertThat(view.getSegments().get(0).getGroups().get(0).get(0))
                .isInstanceOf(MemoryLogUnitProtocol.class);
    }

    @Test
    public void MemoryCorfuDBViewChangeTest() {
        CorfuDBRuntime runtime = new CorfuDBRuntime("memory");
        CorfuDBView view = runtime.getView();
        assertNotNull(view);
        ConfigurationMaster cm = new ConfigurationMaster(runtime);
        cm.resetAll();
        view = runtime.getView();
        assertNotNull(view);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void AllStreamsCanBeCreatedByRuntime(){
        CorfuDBRuntime runtime = new CorfuDBRuntime("memory");
        HashSet<Class<? extends IStream>> streams = new HashSet<Class<? extends IStream>>();
        Reflections reflections = new Reflections("org.corfudb.runtime.stream", new SubTypesScanner(false));
        Set<Class<? extends Object>> allClasses = reflections.getSubTypesOf(Object.class);

        for(Class<? extends Object> c : allClasses)
        {
            try {
                if (Arrays.asList(c.getInterfaces()).contains(IStream.class) && !c.isInterface())
                {
                    streams.add((Class<? extends IStream>) c);
                }
            }
            catch (Exception e)
            {
            }
        }

        streams.stream().forEach(p -> {
            try {
                IStream stream = runtime.openStream(UUID.nameUUIDFromBytes(new byte[]{0, 0, 0, 0, 0, 0 ,0 ,0,
                                                                                        0, 0, 0, 0, 0, 0, 0, 0}), p);
                assertThat(stream)
                        .isInstanceOf(IStream.class);
            }
            catch (Exception e)
            {
                Assert.fail("Exception while creating stream of type " + p.getName() + ": " + e.getMessage());
            }
        });
    }
}
