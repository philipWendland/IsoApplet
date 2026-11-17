package xyz.wendland.javacard.pki.isoapplet;

import apdu4j.core.BIBO;
import javacard.framework.AID;
import pro.javacard.engine.JavaCardEngine;

/**
 * A freshly installed IsoApplet in its own JCardEngine instance.
 *
 * All JCardEngine calls belong in this class, because the engine's API may still change.
 */
final class TestCard implements AutoCloseable {
    static final byte[] APPLET_AID = hex("F276A288BCFBA69D34F31001");

    private final BIBO connection;

    private TestCard(BIBO connection) {
        this.connection = connection;
    }

    /**
     * Installs the applet on a new engine.
     *
     * @param installParameters the applet specific parameters, i.e. the content of tag C9.
     *                          The engine puts the instance AID and privileges in front.
     */
    static TestCard install(byte... installParameters) {
        JavaCardEngine engine = JavaCardEngine.create();
        engine.installApplet(new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length), IsoApplet.class, installParameters);
        return new TestCard(engine.connect("T=1"));
    }

    /** Sends a raw command APDU and returns the raw response, including the status word. */
    byte[] transmit(byte[] command) {
        return connection.transceive(command);
    }

    @Override
    public void close() {
        connection.close();
    }

    static byte[] hex(String s) {
        return java.util.HexFormat.of().parseHex(s.replace(" ", ""));
    }
}
