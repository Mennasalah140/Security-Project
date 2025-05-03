public class VaultDoor8Reverser {

    public static void main(String[] args) {
        char[] expected = {
            (char) 0xF4, (char) 0xC0, (char) 0x97, (char) 0xF0, (char) 0x77, (char) 0x97, (char) 0xC0, (char) 0xE4,
            (char) 0xF0, (char) 0x77, (char) 0xA4, (char) 0xD0, (char) 0xC5, (char) 0x77, (char) 0xF4, (char) 0x86,
            (char) 0xD0, (char) 0xA5, (char) 0x45, (char) 0x96, (char) 0x27, (char) 0xB5, (char) 0x77, (char) 0xD2,
            (char) 0xD0, (char) 0xB4, (char) 0xE1, (char) 0xC1, (char) 0xE0, (char) 0xD0, (char) 0xD0, (char) 0xE0
        };

        System.out.print("Recovered password: ");
        for (char c : expected) {
            char original = unscramble(c);
            System.out.print(original);
        }
        System.out.println(); // newline
    }

    public static char unscramble(char c) {
        // Reverse the scrambling steps in opposite order
        c = switchBits(c, 6, 7);
        c = switchBits(c, 2, 5);
        c = switchBits(c, 3, 4);
        c = switchBits(c, 0, 1);
        c = switchBits(c, 4, 7);
        c = switchBits(c, 5, 6);
        c = switchBits(c, 0, 3);
        c = switchBits(c, 1, 2);
        return c;
    }

    public static char switchBits(char c, int p1, int p2) {
        char mask1 = (char)(1 << p1);
        char mask2 = (char)(1 << p2);
        char bit1 = (char)(c & mask1);
        char bit2 = (char)(c & mask2);
        char rest = (char)(c & ~(mask1 | mask2));
        int shift = p2 - p1;
        char result = (char)((bit1 << shift) | (bit2 >> shift) | rest);
        return result;
    }
}
