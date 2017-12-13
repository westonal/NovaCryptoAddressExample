package com.example;

import io.github.novacrypto.bip39.MnemonicGenerator;
import io.github.novacrypto.bip39.Words;
import io.github.novacrypto.bip39.wordlists.English;

import java.security.SecureRandom;

public final class Main {

    public static void main(String[] args) {
        final String mnemonic = generateNewMnemonic(Words.TWELVE);
        System.out.println(mnemonic);
    }

    private static String generateNewMnemonic(Words wordCount) {
        StringBuilder sb = new StringBuilder();
        byte[] entropy = new byte[wordCount.byteLength()];
        new SecureRandom().nextBytes(entropy);
        new MnemonicGenerator(English.INSTANCE)
                .createMnemonic(entropy, sb::append);
        return sb.toString();
    }
}
