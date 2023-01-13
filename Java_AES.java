import java.io.*;


public class Java_AES {

    public static String[] key;
    public static String[] plaintext;

    static String[] Rcon = {
            "01000000", "02000000", "04000000",
            "08000000", "10000000", "20000000",
            "40000000", "80000000", "1B000000",
            "36000000", "6C000000", "D8000000",
            "AB000000", "4D000000", "9A000000"
    };

    private static final String[][] sbox = {
            {"63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"},
            {"ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"},
            {"b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"},
            {"04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"},
            {"09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"},
            {"53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"},
            {"d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"},
            {"51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"},
            {"cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"},
            {"60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"},
            {"e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"},
            {"e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"},
            {"ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"},
            {"70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"},
            {"e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"},
            {"8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"}
    };

    static String[][] inv_sbox = {
            {"52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb"},
            {"7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb"},
            {"54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e"},
            {"08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25"},
            {"72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92"},
            {"6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84"},
            {"90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06"},
            {"d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b"},
            {"3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73"},
            {"96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e"},
            {"47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b"},
            {"fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4"},
            {"1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f"},
            {"60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef"},
            {"a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61"},
            {"17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d"}
    };

    private static String[] readFile(String filename) {
        StringBuilder fileContents = new StringBuilder();

        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                fileContents.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        String[] temp = fileContents.toString().trim().split("\\s+");

        for (int i = 0; i < temp.length; i++) {
            temp[i] = fixHexLength(temp[i], 2);
        }

        return temp;
    }

    // Read the specified file
    static void loadFiles(String plaintext_file, String key_file) {

        plaintext = readFile(plaintext_file);
        key = readFile(key_file);
    }


    static int hexToInt(String hex) {
        return Integer.parseInt(hex, 16);
    }

    static long hexToLong(String hex) {
        return Long.parseLong(hex, 16);
    }

    static long hexToLong(String[] hexArray) {
        StringBuilder hex = new StringBuilder();
        for (String s : hexArray) {
            hex.append(s);
        }
        return Long.parseLong(hex.toString(), 16);
    }

    static String binToHex(String bin) {
        return Integer.toHexString(Integer.parseInt(bin, 2));
    }

    static String hexToBin(String hex) {
        hex = hex.toLowerCase();
        for (int i = 0; i < 16; i++) {
            String thisHex = Integer.toHexString(i);
            String withBinary = String.format("%04d", Integer.parseInt(Integer.toBinaryString(i)));
            hex = hex.replaceAll(thisHex, withBinary);
        }
        return hex;
    }

    static String[][] hexToMatrix(String hexKey) {
        String[][] matrix = new String[4][4];
        int curr = 0;

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                matrix[j][i] = hexKey.substring(curr, curr + 2);
                curr = curr + 2;
            }
        }

        return matrix;
    }

    static String[][] hexToMatrix(String[] hexKey) {
        String[][] matrix = new String[4][4];
        int curr = 0;

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                matrix[j][i] = hexKey[curr];
                curr++;
            }
        }

        return matrix;
    }

    static String add(String[] hex_list) {
        int size = hex_list.length;
        if (size < 2) {
            return hex_list[0];
        }
        int sum = hexToInt(hex_list[0]);
        for (int i = 1; i < size; i++) {
            sum ^= hexToInt(hex_list[i]);
        }
        return Integer.toHexString(sum);
    }


    // GF(2^8) product
    static String mult(String hexA, String hex) {
        if (hexA.length() == 1) hexA = 0 + hexA;
        if (hex.length() == 1) hex = 0 + hex;

        return switch (hexA) {
            case "02" -> mult_02(hex);
            case "03" -> add(new String[]{mult_02(hex), hex});
            case "09" -> add(new String[]{mult_02(mult_02(mult_02(hex))), hex});
            case "0b" -> add(new String[]{mult_02(mult_02(mult_02(hex))), mult_02(hex), hex});
            case "0d" -> add(new String[]{mult_02(mult_02(mult_02(hex))), mult_02(mult_02(hex)), hex});
            case "0e" -> add(new String[]{mult_02(mult_02(mult_02(hex))), mult_02(mult_02(hex)), mult_02(hex)});
            default -> "\nRestricted multiplication";
        };
    }

    // GF(2^8) product with 0x02
    private static String mult_02(String hex) {
        String hexProd = "";
        String hexABin = hexToBin(hex);

        // if the leading bit is 1, we add 0x1b to the result
        if (hexABin.charAt(0) == '1') {
            hexProd = Integer.toBinaryString(leftShift(hex));
            hexProd = binToHex(hexProd.substring(1));
            hexProd = add(new String[]{hexProd, "1b"});
            // if the leading bit is 0, the result is returned as-is
        } else if (hexABin.charAt(0) == '0') {
            hexProd = Integer.toBinaryString(leftShift(hex));
            hexProd = binToHex(hexProd);
        }
        return fixHexLength(hexProd, 2);
    }

    // Cyclic permutation
    static String[] RotWord(String word) {
        return new String[]{word.substring(2, 4), word.substring(4, 6), word.substring(6, 8), word.substring(0, 2)};
    }

    // Applies the S-box substitution
    static String[] SubWord(String[] word) {
        return new String[]{readFromBox(word[0]), readFromBox(word[1]), readFromBox(word[2]), readFromBox(word[3])};
    }

    // Generates a key schedule
    static String[] expandKey(String[] key) {
        String[] expandedKey = new String[44];
        String temp;
        int Nk = 4, i = 0;

        while (i < 4) {
            expandedKey[i] = key[4 * i] + key[4 * i + 1] + key[4 * i + 2] + key[4 * i + 3];
            i++;
        }

        i = Nk;

        while (i < expandedKey.length) {
            temp = expandedKey[i - 1];

            if (i % Nk == 0)
                temp = Long.toHexString(hexToLong(SubWord(RotWord(temp))) ^ hexToLong(Rcon[(i / Nk) - 1]));

            expandedKey[i] = Long.toHexString(hexToLong(expandedKey[i - Nk]) ^ hexToLong(temp));
            expandedKey[i] = fixHexLength(expandedKey[i], 8);
            i++;
        }
        return expandedKey;
    }


    // returns the result after applying a left bit shift
    static int leftShift(String target) {
        return Integer.parseInt(target, 16) << 1;
    }

    // Prints the result of the key expansion
    static void keyExpansionOutput(String[] expandedKeys) {
        System.out.println("Key Schedule");
        int nextLine = 0;
        for (String expandedKey : expandedKeys) {
            nextLine++;
            if (nextLine == 4) {
                System.out.print(expandedKey);
                nextLine = 0;
                System.out.println();
            } else {
                System.out.print(expandedKey + ",");
            }
        }
    }

    // Prints the matrix with formatting
    static void printHex(String[][] matrix) {
        System.out.println();
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                System.out.print(matrix[j][i] + " ");
            }
            System.out.print("  ");
        }
        System.out.print("\n");
    }

    static String readFromBox(String location) {
        return sbox[hexToInt(location.substring(0, 1))][hexToInt(location.substring(1, 2))];
    }

    static String readFromInvBox(String location) {
        return inv_sbox[hexToInt(location.substring(0, 1))][hexToInt(location.substring(1, 2))];
    }

    static String fixHexLength(String hex, int limit) {
        StringBuilder temp = new StringBuilder();

        if (hex.length() < limit) {
            int zerosToPrefix = limit - hex.length();
            temp.append("0".repeat(zerosToPrefix));
            temp.append(hex);
        } else {
            temp = new StringBuilder(hex);
        }
        return temp.toString();
    }


    public static String[][] ShiftRows(String[][] state) {
        String[][] shiftedState = new String[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                shiftedState[i][j] = fixHexLength(state[i][(i + j) % 4], 2);
            }
        }

        return shiftedState;
    }

    public static String[][] InvShiftRows(String[][] state) {
        String[][] shiftedState = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                shiftedState[i][j] = fixHexLength(state[i][(4 + j - i) % 4], 2);
            }
        }

        return shiftedState;
    }


    public static String[][] AddRoundKey(String[][] state, String[][] roundKey) {
        String[][] temp = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                temp[i][j] = add(new String[]{state[i][j], roundKey[i][j]});
                temp[i][j] = fixHexLength(temp[i][j], 2);
            }
        }

        return temp;
    }

    public static String[][] InvSubBytes(String[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = readFromInvBox(state[i][j]);
            }
        }
        return state;
    }

    public static String[][] SubBytes(String[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = readFromBox(state[i][j]);
            }
        }
        return state;
    }

    // Replaces the four bytes on a column with the result of a multiplication
    public static String[][] MixColumns(String[][] state) {
        String[][] mixedState = new String[4][4];

        // applies the formula
        for (int c = 0; c < 4; c++) {
            String[] format_1 = {mult("02", state[0][c]), mult("03", state[1][c]), state[2][c], state[3][c]};
            mixedState[0][c] = fixHexLength(add(format_1), 2);

            String[] format_2 = {state[0][c], mult("02", state[1][c]), mult("03", state[2][c]), state[3][c]};
            mixedState[1][c] = fixHexLength(add(format_2), 2);

            String[] format_3 = {state[0][c], state[1][c], mult("02", state[2][c]), mult("03", state[3][c])};
            mixedState[2][c] = fixHexLength(add(format_3), 2);

            String[] format_4 = {mult("03", state[0][c]), state[1][c], state[2][c], mult("02", state[3][c])};
            mixedState[3][c] = fixHexLength(add(format_4), 2);
        }

        return mixedState;
    }

    public static String[][] InvMixColumns(String[][] state) {
        String[][] mixedState = new String[4][4];

        for (int c = 0; c < 4; c++) {
            String[] hex = {"0e", "0b", "0d", "09"};
            for (int i = 0; i < 4; i++) {
                mixedState[i][c] = fixHexLength(add(new String[]{
                                mult(hex[(4 - i) % 4], state[0][c]),
                                mult(hex[(5 - i) % 4], state[1][c]),
                                mult(hex[(6 - i) % 4], state[2][c]),
                                mult(hex[(7 - i) % 4], state[3][c])}),
                        2);
            }
        }
        return mixedState;
    }

    static String[][] Encryption(String[][] plaintext, String[] w) {
        String[][] state = plaintext;
        int position = 0;

        String currWord = w[position++] + w[position++] + w[position++] + w[position++];
        state = AddRoundKey(state, hexToMatrix(currWord));

        for (int i = 1; i <= 9; i++) {
            System.out.println("\nState after call " + i + " to MixColumns()");
            System.out.print("-------------------------------------");
            currWord = w[position++] + w[position++] + w[position++] + w[position++];
            SubBytes(state);
            state = ShiftRows(state);
            state = MixColumns(state);
            printHex(state);
            state = AddRoundKey(state, hexToMatrix(currWord));
        }

        currWord = w[position++] + w[position++] + w[position++] + w[position++];
        SubBytes(state);
        state = ShiftRows(state);
        state = AddRoundKey(state, hexToMatrix(currWord));

        return state;
    }

    // Decrypts the ciphertext
    static String[][] Decryption(String[][] ciphertext, String[] w) {

        String[][] state = ciphertext;
        int position = w.length - 1;

        String currWord = w[position - 3] + w[position - 2] + w[position - 1] + w[position];
        position -= 4;
        state = AddRoundKey(state, hexToMatrix(currWord));

        for (int i = 1; i <= 9; i++) {
            System.out.println("\nState after call " + i + " to InvMixColumns()");
            System.out.print("-------------------------------------");
            currWord = w[position - 3] + w[position - 2] + w[position - 1] + w[position];
            state = InvShiftRows(state);
            InvSubBytes(state);
            state = AddRoundKey(state, hexToMatrix(currWord));
            state = InvMixColumns(state);
            printHex(state);
            position -= 4;
        }

        currWord = w[0] + w[1] + w[2] + w[3];
        state = InvShiftRows(state);
        InvSubBytes(state);
        state = AddRoundKey(state, hexToMatrix(currWord));


        return state;
    }

    public static void main(String[] args) {

        if (args.length != 2) {
            System.out.println("Need plaintext and key!");
            System.exit(0);
        }

        // Reading in the files
        loadFiles(args[0], args[1]);
        String[] key = A3_AES.key;
        String[] roundKeys = expandKey(key);
        String[][] plaintext = hexToMatrix(A3_AES.plaintext);
        String[][] keyMatrix = hexToMatrix(key);

        // Prints necessary information
        System.out.print("Plaintext");
        printHex(plaintext);
        System.out.print("Key");
        printHex(keyMatrix);
        keyExpansionOutput(roundKeys);

        System.out.println("\nENCRYPTION PROCESS");
        System.out.println("------------------");
        System.out.print("Plain Text:");
        printHex(plaintext);
        String[][] ciphertext = Encryption(plaintext, roundKeys);
        System.out.print("\nCipherText");
        printHex(ciphertext);

        System.out.println("\n\n\nDECRYPTION PROCESS");
        System.out.println("------------------");
        System.out.print("CipherText");
        printHex(ciphertext);
        String[][] decrypted = Decryption((ciphertext), roundKeys);
        System.out.print("\nPlaintext:");
        printHex(decrypted);

        System.out.println("\nEnd of processing\n");
    }
}
