package com.example;

import io.github.novacrypto.bip32.PrivateKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip39.MnemonicGenerator;
import io.github.novacrypto.bip39.SeedCalculator;
import io.github.novacrypto.bip39.Words;
import io.github.novacrypto.bip39.wordlists.English;

import java.security.SecureRandom;

public final class Main {

    public static void main(String[] args) {
        final String mnemonic = generateNewMnemonic(Words.TWELVE);
        System.out.println(mnemonic);

        final byte[] seed = new SeedCalculator().calculateSeed(mnemonic, "");

        PrivateKey root = PrivateKey.fromSeed(seed, Bitcoin.TEST_NET);
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
