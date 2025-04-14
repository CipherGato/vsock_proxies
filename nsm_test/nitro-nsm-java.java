import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

/**
 * NitroSecureModuleClient - A Java client for interacting with AWS Nitro Secure Module (NSM)
 * via the /dev/nsm device interface.
 */
public class NitroSecureModuleClient {
    // NSM device path
    private static final String NSM_DEVICE_PATH = "/dev/nsm";
    
    // NSM command IDs as defined in the AWS Nitro documentation
    private static final int NSM_DESCRIBE_DEVICE = 1;
    private static final int NSM_GENERATE_RANDOM = 2;
    private static final int NSM_GET_PUBLIC_KEY = 3;
    private static final int NSM_SIGN_DATA = 4;
    private static final int NSM_GET_ATTESTATION_DOC = 5;
    
    // NSM request header size in bytes
    private static final int NSM_REQUEST_HEADER_SIZE = 16;
    
    // File handles for reading from and writing to the NSM device
    private FileInputStream nsmInput;
    private FileOutputStream nsmOutput;
    
    /**
     * Initialize the NSM client by opening file handles to the NSM device.
     * 
     * @throws IOException if the NSM device cannot be accessed
     */
    public void initialize() throws IOException {
        try {
            nsmOutput = new FileOutputStream(NSM_DEVICE_PATH);
            nsmInput = new FileInputStream(NSM_DEVICE_PATH);
            System.out.println("Successfully connected to NSM device at " + NSM_DEVICE_PATH);
        } catch (IOException e) {
            System.err.println("Failed to open NSM device: " + e.getMessage());
            throw e;
        }
    }
    
    /**
     * Close the NSM client by closing the file handles to the NSM device.
     */
    public void close() {
        try {
            if (nsmInput != null) nsmInput.close();
            if (nsmOutput != null) nsmOutput.close();
            System.out.println("Closed connection to NSM device");
        } catch (IOException e) {
            System.err.println("Error closing NSM device handles: " + e.getMessage());
        }
    }
    
    /**
     * Describe the NSM device capabilities.
     * 
     * @return byte array containing the device description response
     * @throws IOException if communication with the NSM device fails
     */
    public byte[] describeDevice() throws IOException {
        // Construct a simple request with no additional data
        ByteBuffer requestBuffer = ByteBuffer.allocate(NSM_REQUEST_HEADER_SIZE);
        requestBuffer.order(ByteOrder.LITTLE_ENDIAN);
        
        // Request ID (UUID) - using a random UUID for this example
        UUID requestId = UUID.randomUUID();
        requestBuffer.putLong(requestId.getMostSignificantBits());
        requestBuffer.putLong(requestId.getLeastSignificantBits());
        
        // Command ID for Describe Device
        requestBuffer.putInt(NSM_DESCRIBE_DEVICE);
        
        // Version of the command
        requestBuffer.putInt(0);
        
        // No additional data for this command
        
        // Send request to the NSM device
        byte[] request = requestBuffer.array();
        nsmOutput.write(request);
        nsmOutput.flush();
        
        // Read the response
        // First read the response header to determine the total size
        byte[] responseHeader = new byte[16];
        int bytesRead = nsmInput.read(responseHeader, 0, responseHeader.length);
        
        if (bytesRead != responseHeader.length) {
            throw new IOException("Failed to read complete response header");
        }
        
        ByteBuffer headerBuffer = ByteBuffer.wrap(responseHeader);
        headerBuffer.order(ByteOrder.LITTLE_ENDIAN);
        
        // Skip the first 8 bytes (response ID)
        headerBuffer.position(8);
        
        // Read the response length
        int responseLength = headerBuffer.getInt();
        
        // Allocate buffer for the full response (including header)
        byte[] fullResponse = new byte[responseLength];
        System.arraycopy(responseHeader, 0, fullResponse, 0, responseHeader.length);
        
        // Read the remainder of the response
        bytesRead = nsmInput.read(fullResponse, responseHeader.length, responseLength - responseHeader.length);
        
        if (bytesRead != responseLength - responseHeader.length) {
            throw new IOException("Failed to read complete response");
        }
        
        return fullResponse;
    }
    
    /**
     * Generate random bytes using the NSM's hardware random number generator.
     * 
     * @param numBytes number of random bytes to generate
     * @return array of random bytes
     * @throws IOException if communication with the NSM device fails
     */
    public byte[] generateRandom(int numBytes) throws IOException {
        // Calculate total request size: header + size field + requested random bytes
        int requestSize = NSM_REQUEST_HEADER_SIZE + 4;
        
        ByteBuffer requestBuffer = ByteBuffer.allocate(requestSize);
        requestBuffer.order(ByteOrder.LITTLE_ENDIAN);
        
        // Request ID (UUID)
        UUID requestId = UUID.randomUUID();
        requestBuffer.putLong(requestId.getMostSignificantBits());
        requestBuffer.putLong(requestId.getLeastSignificantBits());
        
        // Command ID for Generate Random
        requestBuffer.putInt(NSM_GENERATE_RANDOM);
        
        // Version of the command
        requestBuffer.putInt(0);
        
        // Number of random bytes to generate
        requestBuffer.putInt(numBytes);
        
        // Send request to the NSM device
        byte[] request = requestBuffer.array();
        nsmOutput.write(request);
        nsmOutput.flush();
        
        // Read the response header
        byte[] responseHeader = new byte[16];
        int bytesRead = nsmInput.read(responseHeader, 0, responseHeader.length);
        
        if (bytesRead != responseHeader.length) {
            throw new IOException("Failed to read complete response header");
        }
        
        ByteBuffer headerBuffer = ByteBuffer.wrap(responseHeader);
        headerBuffer.order(ByteOrder.LITTLE_ENDIAN);
        
        // Skip the first 8 bytes (response ID)
        headerBuffer.position(8);
        
        // Read the response length
        int responseLength = headerBuffer.getInt();
        
        // Status code
        int statusCode = headerBuffer.getInt();
        
        if (statusCode != 0) {
            throw new IOException("NSM operation failed with status code: " + statusCode);
        }
        
        // Allocate buffer for the full response
        byte[] fullResponse = new byte[responseLength];
        System.arraycopy(responseHeader, 0, fullResponse, 0, responseHeader.length);
        
        // Read the remainder of the response
        bytesRead = nsmInput.read(fullResponse, responseHeader.length, responseLength - responseHeader.length);
        
        if (bytesRead != responseLength - responseHeader.length) {
            throw new IOException("Failed to read complete response");
        }
        
        // Extract the random bytes from the response
        // The random bytes start after the header and status fields
        byte[] randomBytes = new byte[numBytes];
        System.arraycopy(fullResponse, 20, randomBytes, 0, numBytes);
        
        return randomBytes;
    }
    
    /**
     * Generate an attestation document using the NSM.
     * 
     * @param userData optional user data to include in the attestation document
     * @param userDataMode the mode for handling user data (0 = include directly, 1 = include hash)
     * @return byte array containing the attestation document
     * @throws IOException if communication with the NSM device fails
     */
    public byte[] getAttestationDocument(byte[] userData, int userDataMode) throws IOException {
        // Calculate total request size: header + user data mode + user data length + user data
        int requestSize = NSM_REQUEST_HEADER_SIZE + 4 + 4 + userData.length;
        
        ByteBuffer requestBuffer = ByteBuffer.allocate(requestSize);
        requestBuffer.order(ByteOrder.LITTLE_ENDIAN);
        
        // Request ID (UUID)
        UUID requestId = UUID.randomUUID();
        requestBuffer.putLong(requestId.getMostSignificantBits());
        requestBuffer.putLong(requestId.getLeastSignificantBits());
        
        // Command ID for Get Attestation Document
        requestBuffer.putInt(NSM_GET_ATTESTATION_DOC);
        
        // Version of the command
        requestBuffer.putInt(0);
        
        // User data mode (0 = include data directly, 1 = include hash of data)
        requestBuffer.putInt(userDataMode);
        
        // User data length
        requestBuffer.putInt(userData.length);
        
        // User data (if any)
        if (userData.length > 0) {
            requestBuffer.put(userData);
        }
        
        // Send request to the NSM device
        byte[] request = requestBuffer.array();
        nsmOutput.write(request);
        nsmOutput.flush();
        
        // Read the response header
        byte[] responseHeader = new byte[16];
        int bytesRead = nsmInput.read(responseHeader, 0, responseHeader.length);
        
        if (bytesRead != responseHeader.length) {
            throw new IOException("Failed to read complete response header");
        }
        
        ByteBuffer headerBuffer = ByteBuffer.wrap(responseHeader);
        headerBuffer.order(ByteOrder.LITTLE_ENDIAN);
        
        // Skip the first 8 bytes (response ID)
        headerBuffer.position(8);
        
        // Read the response length
        int responseLength = headerBuffer.getInt();
        
        // Status code
        int statusCode = headerBuffer.getInt();
        
        if (statusCode != 0) {
            throw new IOException("NSM attestation operation failed with status code: " + statusCode);
        }
        
        // Allocate buffer for the full response
        byte[] fullResponse = new byte[responseLength];
        System.arraycopy(responseHeader, 0, fullResponse, 0, responseHeader.length);
        
        // Read the remainder of the response
        bytesRead = nsmInput.read(fullResponse, responseHeader.length, responseLength - responseHeader.length);
        
        if (bytesRead != responseLength - responseHeader.length) {
            throw new IOException("Failed to read complete response");
        }
        
        // Extract the attestation document from the response
        // The document size is specified in the next 4 bytes after the header
        ByteBuffer docBuffer = ByteBuffer.wrap(fullResponse, 20, 4);
        docBuffer.order(ByteOrder.LITTLE_ENDIAN);
        int docSize = docBuffer.getInt();
        
        // Extract the attestation document
        byte[] attestationDoc = new byte[docSize];
        System.arraycopy(fullResponse, 24, attestationDoc, 0, docSize);
        
        return attestationDoc;
    }
    
    /**
     * Save attestation document to a file.
     * 
     * @param attestationDoc the attestation document as a byte array
     * @param filePath path to save the document
     * @throws IOException if the file cannot be written
     */
    public void saveAttestationDocument(byte[] attestationDoc, String filePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(attestationDoc);
        }
        System.out.println("Attestation document saved to: " + filePath);
    }
    
    /**
     * Parse and display the NSM device description.
     * 
     * @param response the raw response from the describeDevice call
     */
    public void displayDeviceDescription(byte[] response) {
        ByteBuffer buffer = ByteBuffer.wrap(response);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        
        // Skip header (16 bytes)
        buffer.position(16);
        
        // Read status code
        int statusCode = buffer.getInt();
        System.out.println("Status code: " + statusCode);
        
        if (statusCode != 0) {
            System.out.println("Error: NSM device returned error status");
            return;
        }
        
        // Parse device description fields
        // This is a simplified example - actual structure would be based on NSM documentation
        int version = buffer.getInt();
        int vendorId = buffer.getInt();
        int deviceId = buffer.getInt();
        int capabilities = buffer.getInt();
        
        System.out.println("NSM Device Description:");
        System.out.println("  Version: " + version);
        System.out.println("  Vendor ID: 0x" + Integer.toHexString(vendorId));
        System.out.println("  Device ID: 0x" + Integer.toHexString(deviceId));
        System.out.println("  Capabilities: 0x" + Integer.toHexString(capabilities));
    }
    
    /**
     * Main method to demonstrate usage of the NSM client.
     */
    public static void main(String[] args) {
        NitroSecureModuleClient nsmClient = new NitroSecureModuleClient();
        
        try {
            // Initialize the NSM client
            nsmClient.initialize();
            
            // Describe the NSM device
            System.out.println("Querying NSM device description...");
            byte[] deviceDescription = nsmClient.describeDevice();
            nsmClient.displayDeviceDescription(deviceDescription);
            
            // Generate random bytes
            int randomBytesCount = 32;
            System.out.println("\nGenerating " + randomBytesCount + " random bytes...");
            byte[] randomBytes = nsmClient.generateRandom(randomBytesCount);
            System.out.println("Random bytes: " + bytesToHex(randomBytes));
            
            // Generate attestation document
            System.out.println("\nGenerating attestation document...");
            byte[] attestationDoc = nsmClient.getAttestationDocument(new byte[0], 0);
            System.out.println("Attestation document received (" + attestationDoc.length + " bytes)");
            System.out.println("First 32 bytes: " + bytesToHex(Arrays.copyOf(attestationDoc, 32)) + "...");
            
        } catch (IOException e) {
            System.err.println("Error interacting with NSM device: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Close the NSM client
            nsmClient.close();
        }
    }
    
    /**
     * Utility method to convert a byte array to a hexadecimal string.
     * 
     * @param bytes the byte array to convert
     * @return a string of hexadecimal characters
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
