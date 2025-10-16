import java.util.Base64;

public class Base64Decoder {

    public static void main(String[] args) {
        String encodedString = "vJqfip28ioydips=";

        try {
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] decodedBytes = decoder.decode(encodedString);

            String decodedString = new String(decodedBytes);

            System.out.println("Original Base64 String: " + encodedString);
            System.out.println("Decoded Bytes: " + java.util.Arrays.toString(decodedBytes));
            System.out.println("Decoded String: " + decodedString);

        } catch (IllegalArgumentException e) {
            System.err.println("Error decoding Base64 string: " + e.getMessage());
        }
    }
}