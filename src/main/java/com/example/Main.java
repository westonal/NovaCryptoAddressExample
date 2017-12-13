package com.example;

import io.github.novacrypto.bip32.PrivateKey;
import io.github.novacrypto.bip32.PublicKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip39.MnemonicGenerator;
import io.github.novacrypto.bip39.SeedCalculator;
import io.github.novacrypto.bip39.Words;
import io.github.novacrypto.bip39.wordlists.English;
import io.github.novacrypto.bip44.Account;
import io.github.novacrypto.bip44.AddressIndex;
import io.github.novacrypto.bip44.Change;

import java.security.SecureRandom;

import static io.github.novacrypto.bip44.BIP44.m;

public final class Main {

    public static void main(String[] args) {
        final String mnemonic = generateNewMnemonic(Words.TWELVE);
        System.out.println(mnemonic);

        final byte[] seed = new SeedCalculator().calculateSeed(mnemonic, "");

        PrivateKey root = PrivateKey.fromSeed(seed, Bitcoin.TEST_NET);

        final Account account =
                m().purpose44()
                        .coinType(1)
                        .account(0);
        final PublicKey accountKey = root.derive(account, Account.DERIVATION)
                .neuter();

        for (int i = 0; i < 20; i++) {
            final AddressIndex derivationPath = account.external().address(i);
            final PublicKey publicKey = accountKey.derive(derivationPath, AddressIndex.DERIVATION_FROM_ACCOUNT);
            System.out.println(derivationPath + " = " + publicKey.p2pkhAddress());
        }
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
