package xyz.wendland.javacard.pki.isoapplet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HexFormat;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Checks that the applet runs in JCardEngine, and that install parameters reach it. */
class SmokeTest {
    private static final byte[] SELECT = TestCard.hex("00 A4 04 00 0C F276A288BCFBA69D34F31001");
    private static final byte[] GET_DATA_VERSION_AND_FEATURES = TestCard.hex("00 CA 01 01 03");

    /** With every valid install parameter, the freshly installed applet can be selected: 9000. */
    @ParameterizedTest(name = "install parameters [{0}]")
    @ValueSource(strings = {"", "800100", "800101", "800102"})
    void select_validInstallParameters_returns9000(String installParameters) {
        // Arrange
        try (TestCard card = TestCard.install(TestCard.hex(installParameters))) {
            // Act
            byte[] response = card.transmit(SELECT);

            // Assert
            assertEquals("9000", toHex(response));
        }
    }

    /**
     * GET DATA 0101 returns the API version (0100), the features byte and 9000.
     * All features are present on the engine, except that tag 80 with value 01 hides RSA-4096 (bit 20).
     */
    @ParameterizedTest(name = "install parameters [{0}]")
    @CsvSource({
        "'',       01002F9000",
        "800100,   01002F9000",
        "800101,   01000F9000",
        "800102,   01002F9000",
    })
    void getDataVersionAndFeatures_installParameters_returnsFeaturesByte(String installParameters, String expected) {
        // Arrange
        try (TestCard card = TestCard.install(TestCard.hex(installParameters))) {
            ok(card.transmit(SELECT));

            // Act
            byte[] response = card.transmit(GET_DATA_VERSION_AND_FEATURES);

            // Assert
            assertEquals(expected, toHex(response));
        }
    }

    /** Invalid install parameters make the installation fail. The first three are the unreleased positional format, which must not be misread as TLV. */
    @ParameterizedTest(name = "install parameters [{0}]")
    @ValueSource(strings = {
        "00", "01", "02",
        "8000",         // no value
        "8001",         // value missing
        "800103",       // unknown value
        "80020100",     // value too long
        "810102",       // unknown tag
        "800102810100", // unknown tag after a valid entry
        "800101800102", // tag given twice
    })
    void install_invalidParameters_throws(String installParameters) {
        // Arrange
        byte[] parameters = TestCard.hex(installParameters);

        // Act
        Executable install = () -> TestCard.install(parameters).close();

        // Assert
        assertThrows(RuntimeException.class, install);
    }

    /**
     * Install data from every installer gives the RSA-4096 mode of tag 80, or 0 (probe) without parameters.
     * The installers differ: OpenSC CI sends jCardSim a CREATE APPLET with two fields, and jCardSim can
     * also install with no data at all. Fields are length-value encoded: instance AID, control
     * information, install parameters.
     */
    @ParameterizedTest(name = "install data [{0}]")
    @CsvSource({
        "'',                                                            0",
        "0C F276A288BCFBA69D34F31001,                                   0",
        "0C F276A288BCFBA69D34F31001 0C F276A288BCFBA69D34F31001,       0",
        "0C F276A288BCFBA69D34F31001 00 00,                             0",
        "0C F276A288BCFBA69D34F31001 00 03 800102,                      2",
    })
    void parseRsa4096Mode_installDataLayouts_returnsMode(String installData, byte expectedMode) {
        // Arrange
        byte[] data = TestCard.hex(installData);

        // Act
        byte mode = IsoApplet.parseRsa4096Mode(data, (short) 0, (byte) data.length);

        // Assert
        assertEquals(expectedMode, mode);
    }

    /** jCardSim and real cards pass the install data inside a larger buffer: at offset 5, mode 02 is still found. */
    @Test
    void parseRsa4096Mode_dataAtOffset5_returnsMode2() {
        // Arrange
        byte[] data = TestCard.hex("FFFFFFFFFF 0C F276A288BCFBA69D34F31001 00 03 800102");

        // Act
        byte mode = IsoApplet.parseRsa4096Mode(data, (short) 5, (byte) (data.length - 5));

        // Assert
        assertEquals(2, mode);
    }

    /** A parameter field whose length does not match its content is refused with 6A80 (wrong data). */
    @ParameterizedTest(name = "install data [{0}]")
    @ValueSource(strings = {
        "0C F276A288BCFBA69D34F31001 00 04 800102", // more parameters announced than present
        "0C F276A288BCFBA69D34F31001 00 01 02",     // one byte, not a TLV entry
    })
    void parseRsa4096Mode_parameterLengthMismatch_throwsWrongData(String installData) {
        // Arrange
        byte[] data = TestCard.hex(installData);

        // Act
        Executable parse = () -> IsoApplet.parseRsa4096Mode(data, (short) 0, (byte) data.length);

        // Assert
        ISOException e = assertThrows(ISOException.class, parse);
        assertEquals(ISO7816.SW_WRONG_DATA, e.getReason());
    }

    /** Parameters that reach past the given install data length are refused with 6A80, even if the buffer holds them. */
    @Test
    void parseRsa4096Mode_parametersBeyondInstallDataLength_throwsWrongData() {
        // Arrange
        byte[] data = TestCard.hex("0C F276A288BCFBA69D34F31001 00 03 800102");

        // Act
        Executable parse = () -> IsoApplet.parseRsa4096Mode(data, (short) 0, (byte) (data.length - 1));

        // Assert
        ISOException e = assertThrows(ISOException.class, parse);
        assertEquals(ISO7816.SW_WRONG_DATA, e.getReason());
    }

    /** Asserts status word 9000. For Arrange steps whose answer is not under test. */
    private static void ok(byte[] response) {
        assertEquals("9000", toHex(response), "setup step failed");
    }

    private static String toHex(byte[] bytes) {
        return HexFormat.of().withUpperCase().formatHex(bytes);
    }
}
