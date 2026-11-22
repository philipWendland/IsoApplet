package xyz.wendland.javacard.pki.isoapplet;

import static org.junit.jupiter.api.Assertions.assertEquals;

import javacard.framework.CardRuntimeException;
import javacard.framework.ISOException;
import javacard.framework.SystemException;
import javacard.framework.TransactionException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Checks which exceptions process() reports as 6A84 ("not enough memory space") instead of 6F00.
 *
 * JCardEngine has no memory limit and no transaction buffer limit, so no APDU can make it run out of memory.
 * These tests therefore call the mapping directly; the path through process() is proven on a real card only
 * (test/realcard_memory_full.py in the workspace).
 */
class MemoryShortageTest {

    /**
     * Exceptions that signal a lack of memory map to 6A84; every other exception maps to 9000, which means
     * that process() rethrows it unchanged and the runtime answers as before. An ISOException is never mapped,
     * even if its reason is 5, the value of SystemException.NO_RESOURCE.
     */
    @ParameterizedTest(name = "{0} {1}")
    @CsvSource({
        "SystemException,      NO_RESOURCE,        6A84",
        "SystemException,      NO_TRANSIENT_SPACE, 6A84",
        "TransactionException, BUFFER_FULL,        6A84",
        "SystemException,      ILLEGAL_VALUE,      9000",
        "SystemException,      ILLEGAL_USE,        9000",
        "TransactionException, IN_PROGRESS,        9000",
        "TransactionException, INTERNAL_FAILURE,   9000",
        "ISOException,         5,                  9000",
    })
    void statusWordForMemoryShortage_exception_returnsStatusWord(String type, String reason, String expected) {
        // Arrange
        CardRuntimeException exception = exception(type, reason);

        // Act
        short statusWord = IsoApplet.statusWordForMemoryShortage(exception);

        // Assert
        assertEquals(expected, String.format("%04X", statusWord & 0xFFFF));
    }

    private static CardRuntimeException exception(String type, String reason) {
        switch (type) {
            case "SystemException":
                return new SystemException(switch (reason) {
                    case "ILLEGAL_VALUE" -> SystemException.ILLEGAL_VALUE;
                    case "NO_TRANSIENT_SPACE" -> SystemException.NO_TRANSIENT_SPACE;
                    case "NO_RESOURCE" -> SystemException.NO_RESOURCE;
                    case "ILLEGAL_USE" -> SystemException.ILLEGAL_USE;
                    default -> throw new IllegalArgumentException(reason);
                });
            case "TransactionException":
                return new TransactionException(switch (reason) {
                    case "IN_PROGRESS" -> TransactionException.IN_PROGRESS;
                    case "BUFFER_FULL" -> TransactionException.BUFFER_FULL;
                    case "INTERNAL_FAILURE" -> TransactionException.INTERNAL_FAILURE;
                    default -> throw new IllegalArgumentException(reason);
                });
            case "ISOException":
                return new ISOException(Short.parseShort(reason));
            default:
                throw new IllegalArgumentException(type);
        }
    }
}
