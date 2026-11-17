package xyz.wendland.javacard.pki.isoapplet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Cipher;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Exercises the cryptographic features with the APDUs OpenSC sends, using extended length
 * as OpenSC does on a card with that feature. Results are checked with the JDK's providers,
 * not with the engine's, so that the engine does not vouch for itself.
 *
 * Le matters here: JCardEngine truncates an Ne of 65536 to 0 instead of returning 32767 from
 * setOutgoing(), so the applet answers 6C00 to a signature command with Le=0000. OpenSC only
 * sends Le=0000 for key generation, and the output length for private key operations.
 */
class CryptoTest {
    private static final byte ALG_GEN_RSA_2048 = (byte) 0xF3;
    private static final byte ALG_GEN_RSA_4096 = (byte) 0xF5;
    private static final byte ALG_GEN_EC = (byte) 0xEC;
    private static final byte ALG_RSA_PKCS1 = 0x11;
    private static final byte ALG_RSA_PSS = 0x12;
    private static final byte ALG_ECDSA = 0x21;

    private static final byte SET_KEY_GENERATION = 0x00;
    private static final byte SET_SIGNATURE = (byte) 0xB6;
    private static final byte SET_DECRYPTION = (byte) 0xB8;

    private static final byte KEY_REF = 0x00;
    private static final int MAX_LE = 65536;
    private static final byte[] SELECT = TestCard.hex("00 A4 04 00 0C F276A288BCFBA69D34F31001");
    private static final byte[] PIN = "123456".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PUK = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * PSO COMPUTE DIGITAL SIGNATURE with RSA-PSS over a precomputed hash gives a signature the JDK verifies.
     * The salt is as long as the hash, except that JCardEngine hard-codes 16 bytes for SHA-1 (a bug, it
     * should be 20; a real card uses 20). RSA-4096 only works with extended APDUs: the signature exceeds 255 bytes.
     */
    @ParameterizedTest(name = "RSA-{0}, {1}, salt {2}")
    @CsvSource({
        "2048, SHA-1,   16",
        "2048, SHA-224, 28",
        "2048, SHA-256, 32",
        "2048, SHA-384, 48",
        "2048, SHA-512, 64",
        "4096, SHA-256, 32",
    })
    void computeSignature_rsaPss_verifies(int keySize, String hash, int saltLength) throws Exception {
        // Arrange
        try (TestCard card = personalizedCard()) {
            PublicKey key = generateRsaKey(card, keySize);
            byte[] message = randomBytes(300);
            byte[] digest = MessageDigest.getInstance(hash).digest(message);
            setSecurityEnvironment(card, SET_SIGNATURE, ALG_RSA_PSS);

            // Act
            byte[] response = card.transmit(extended(0x2A, 0x9E, 0x9A, digest, keySize / 8));

            // Assert
            byte[] signature = ok(response);
            assertTrue(pssVerifies(key, hash, saltLength, message, signature), "PSS signature does not verify");
        }
    }

    /** PSO COMPUTE DIGITAL SIGNATURE with RSA PKCS#1 v1.5 over a SHA-256 DigestInfo gives a signature the JDK verifies. */
    @ParameterizedTest(name = "RSA-{0}")
    @ValueSource(ints = {2048, 4096})
    void computeSignature_rsaPkcs1Sha256_verifies(int keySize) throws Exception {
        // Arrange
        try (TestCard card = personalizedCard()) {
            PublicKey key = generateRsaKey(card, keySize);
            byte[] message = randomBytes(300);
            byte[] digestInfo = sha256DigestInfo(message);
            setSecurityEnvironment(card, SET_SIGNATURE, ALG_RSA_PKCS1);

            // Act
            byte[] response = card.transmit(extended(0x2A, 0x9E, 0x9A, digestInfo, keySize / 8));

            // Assert
            byte[] signature = ok(response);
            assertTrue(pkcs1Verifies(key, message, signature), "PKCS#1 signature does not verify");
        }
    }

    /** PSO DECIPHER with RSA PKCS#1 v1.5 returns the plaintext the JDK encrypted, at the longest plaintext the key allows. */
    @ParameterizedTest(name = "RSA-{0}")
    @ValueSource(ints = {2048, 4096})
    void decipher_rsaPkcs1_returnsPlaintext(int keySize) throws Exception {
        // Arrange
        try (TestCard card = personalizedCard()) {
            PublicKey key = generateRsaKey(card, keySize);
            byte[] plaintext = randomBytes(keySize / 8 - 11);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] ciphertext = cipher.doFinal(plaintext);
            // The first byte is the padding indicator.
            byte[] data = new byte[ciphertext.length + 1];
            System.arraycopy(ciphertext, 0, data, 1, ciphertext.length);
            setSecurityEnvironment(card, SET_DECRYPTION, ALG_RSA_PKCS1);

            // Act
            byte[] response = card.transmit(extended(0x2A, 0x80, 0x86, data, keySize / 8));

            // Assert
            assertArrayEquals(plaintext, ok(response));
        }
    }

    /** PSO COMPUTE DIGITAL SIGNATURE with ECDSA gets a precomputed hash and returns a DER signature ("raw ECDSA") the JDK verifies. */
    @ParameterizedTest(name = "{0}, {1}")
    @CsvSource({"secp256r1, SHA-256", "secp384r1, SHA-384"})
    void computeSignature_ecdsaOverPrecomputedHash_verifies(String curveName, String hash) throws Exception {
        // Arrange
        ECParameterSpec curve = curve(curveName);
        try (TestCard card = personalizedCard()) {
            PublicKey key = generateEcKey(card, curve);
            byte[] digest = MessageDigest.getInstance(hash).digest(randomBytes(300));
            setSecurityEnvironment(card, SET_SIGNATURE, ALG_ECDSA);

            // Act
            byte[] response = card.transmit(extended(0x2A, 0x9E, 0x9A, digest, 256));

            // Assert
            byte[] signature = ok(response);
            assertTrue(ecdsaVerifies(key, digest, signature), "ECDSA signature does not verify");
        }
    }

    /** GENERATE ASYMMETRIC KEY PAIR for RSA returns a 7F49 template with a modulus of the requested size. */
    @ParameterizedTest(name = "RSA-{0}")
    @ValueSource(ints = {2048, 4096})
    void generateKeyPair_rsa_returnsModulusOfKeySize(int keySize) throws Exception {
        // Arrange
        try (TestCard card = personalizedCard()) {
            setSecurityEnvironment(card, SET_KEY_GENERATION, keySize == 4096 ? ALG_GEN_RSA_4096 : ALG_GEN_RSA_2048);

            // Act
            byte[] response = card.transmit(extended(0x46, 0x42, 0x00, new byte[0], MAX_LE));

            // Assert
            BigInteger modulus = new BigInteger(1, valueOf(ok(response), 0x81));
            assertEquals(keySize, modulus.bitLength());
        }
    }

    /** GENERATE ASYMMETRIC KEY PAIR for EC returns a 7F49 template with the public point in uncompressed form (04 X Y). */
    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"secp256r1", "secp384r1"})
    void generateKeyPair_ec_returnsUncompressedPoint(String curveName) throws Exception {
        // Arrange
        ECParameterSpec curve = curve(curveName);
        int size = (curve.getCurve().getField().getFieldSize() + 7) / 8;
        try (TestCard card = personalizedCard()) {
            setSecurityEnvironment(card, SET_KEY_GENERATION, ALG_GEN_EC);

            // Act
            byte[] response = card.transmit(extended(0x46, 0x00, 0x00, encodeCurve(curve), MAX_LE));

            // Assert
            byte[] point = valueOf(ok(response), 0x86);
            assertEquals(0x04, point[0], "public point must be uncompressed");
            assertEquals(1 + 2 * size, point.length);
        }
    }

    private static TestCard personalizedCard() {
        TestCard card = TestCard.install();
        ok(card.transmit(SELECT));
        ok(card.transmit(shortCommand(0x24, 0x01, 0x02, PUK)));
        ok(card.transmit(shortCommand(0x24, 0x01, 0x01, PIN)));
        ok(card.transmit(shortCommand(0x20, 0x00, 0x01, PIN)));
        return card;
    }

    /** Generates an RSA key in slot KEY_REF, for Arrange steps. The generation itself is tested in generateKeyPair_rsa_returnsModulusOfKeySize. */
    private static PublicKey generateRsaKey(TestCard card, int keySize) throws Exception {
        setSecurityEnvironment(card, SET_KEY_GENERATION, keySize == 4096 ? ALG_GEN_RSA_4096 : ALG_GEN_RSA_2048);
        byte[] template = ok(card.transmit(extended(0x46, 0x42, 0x00, new byte[0], MAX_LE)));
        BigInteger modulus = new BigInteger(1, valueOf(template, 0x81));
        BigInteger exponent = new BigInteger(1, valueOf(template, 0x82));
        return KeyFactory.getInstance("RSA", "SunRsaSign").generatePublic(new RSAPublicKeySpec(modulus, exponent));
    }

    /** Generates an EC key in slot KEY_REF, for Arrange steps. The generation itself is tested in generateKeyPair_ec_returnsUncompressedPoint. */
    private static PublicKey generateEcKey(TestCard card, ECParameterSpec curve) throws Exception {
        setSecurityEnvironment(card, SET_KEY_GENERATION, ALG_GEN_EC);
        byte[] template = ok(card.transmit(extended(0x46, 0x00, 0x00, encodeCurve(curve), MAX_LE)));
        return decodeEcPublicKey(template, curve);
    }

    private static ECParameterSpec curve(String curveName) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(curveName));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }

    private static byte[] sha256DigestInfo(byte[] message) throws Exception {
        byte[] digestInfoPrefix = TestCard.hex("3031300D060960864801650304020105000420");
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(message);
        byte[] digestInfo = Arrays.copyOf(digestInfoPrefix, digestInfoPrefix.length + digest.length);
        System.arraycopy(digest, 0, digestInfo, digestInfoPrefix.length, digest.length);
        return digestInfo;
    }

    private static boolean pssVerifies(PublicKey key, String hash, int saltLength, byte[] message, byte[] signature)
            throws Exception {
        Signature verifier = Signature.getInstance("RSASSA-PSS", "SunRsaSign");
        verifier.setParameter(new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(hash), saltLength, 1));
        verifier.initVerify(key);
        verifier.update(message);
        return verifier.verify(signature);
    }

    private static boolean pkcs1Verifies(PublicKey key, byte[] message, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA", "SunRsaSign");
        verifier.initVerify(key);
        verifier.update(message);
        return verifier.verify(signature);
    }

    private static boolean ecdsaVerifies(PublicKey key, byte[] digest, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance("NONEwithECDSA", "SunEC");
        verifier.initVerify(key);
        verifier.update(digest);
        return verifier.verify(signature);
    }

    private static void setSecurityEnvironment(TestCard card, byte template, byte algorithm) {
        byte[] data = {(byte) 0x80, 0x01, algorithm, (byte) 0x84, 0x01, KEY_REF};
        ok(card.transmit(shortCommand(0x22, 0x41, template, data)));
    }

    private static byte[] encodeCurve(ECParameterSpec spec) {
        EllipticCurve curve = spec.getCurve();
        int size = (curve.getField().getFieldSize() + 7) / 8;
        BigInteger prime = ((java.security.spec.ECFieldFp) curve.getField()).getP();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        putTag(out, 0x81, unsigned(prime, size));
        putTag(out, 0x82, unsigned(curve.getA(), size));
        putTag(out, 0x83, unsigned(curve.getB(), size));
        putTag(out, 0x84, uncompressed(spec.getGenerator(), size));
        putTag(out, 0x85, unsigned(spec.getOrder(), size));
        putTag(out, 0x87, new byte[] {0x00, (byte) spec.getCofactor()});
        return out.toByteArray();
    }

    private static PublicKey decodeEcPublicKey(byte[] template, ECParameterSpec curve) throws Exception {
        byte[] point = valueOf(template, 0x86);
        assertEquals(0x04, point[0], "public point must be uncompressed");
        int size = (point.length - 1) / 2;
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(point, 1, 1 + size));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(point, 1 + size, 1 + 2 * size));
        return KeyFactory.getInstance("EC", "SunEC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), curve));
    }

    private static byte[] uncompressed(ECPoint point, int size) {
        byte[] encoded = new byte[1 + 2 * size];
        encoded[0] = 0x04;
        System.arraycopy(unsigned(point.getAffineX(), size), 0, encoded, 1, size);
        System.arraycopy(unsigned(point.getAffineY(), size), 0, encoded, 1 + size, size);
        return encoded;
    }

    private static byte[] unsigned(BigInteger value, int size) {
        byte[] bytes = value.toByteArray();
        byte[] result = new byte[size];
        int length = Math.min(bytes.length, size);
        System.arraycopy(bytes, bytes.length - length, result, size - length, length);
        return result;
    }

    private static void putTag(ByteArrayOutputStream out, int tag, byte[] value) {
        out.write(tag);
        out.write(value.length);
        out.writeBytes(value);
    }

    /** Finds a one byte tag inside the 7F49 public key template. */
    private static byte[] valueOf(byte[] template, int wantedTag) {
        assertEquals(0x7F, template[0] & 0xFF);
        assertEquals(0x49, template[1] & 0xFF);
        int[] position = {2};
        readLength(template, position);
        while (position[0] < template.length) {
            int tag = template[position[0]++] & 0xFF;
            int length = readLength(template, position);
            if (tag == wantedTag) {
                return Arrays.copyOfRange(template, position[0], position[0] + length);
            }
            position[0] += length;
        }
        throw new AssertionError(String.format("Tag %02X not in %s", wantedTag, HexFormat.of().formatHex(template)));
    }

    private static int readLength(byte[] data, int[] position) {
        int first = data[position[0]++] & 0xFF;
        if (first < 0x80) {
            return first;
        }
        int length = 0;
        for (int i = 0; i < (first & 0x7F); i++) {
            length = length << 8 | data[position[0]++] & 0xFF;
        }
        return length;
    }

    private static byte[] shortCommand(int ins, int p1, int p2, byte[] data) {
        byte[] command = new byte[5 + data.length];
        command[1] = (byte) ins;
        command[2] = (byte) p1;
        command[3] = (byte) p2;
        command[4] = (byte) data.length;
        System.arraycopy(data, 0, command, 5, data.length);
        return command;
    }

    /** An extended length command. An Le of 65536 is encoded as 0000. */
    private static byte[] extended(int ins, int p1, int p2, byte[] data, int le) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[] {0x00, (byte) ins, (byte) p1, (byte) p2, 0x00});
        if (data.length > 0) {
            out.write(data.length >> 8);
            out.write(data.length);
            out.writeBytes(data);
        }
        out.write(le >> 8);
        out.write(le);
        return out.toByteArray();
    }

    /** Asserts status word 9000 and returns the response data. */
    private static byte[] ok(byte[] response) {
        int statusWord = (response[response.length - 2] & 0xFF) << 8 | response[response.length - 1] & 0xFF;
        assertEquals("9000", String.format("%04X", statusWord));
        return Arrays.copyOf(response, response.length - 2);
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}
