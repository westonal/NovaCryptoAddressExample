package com.example;

import io.github.novacrypto.bip32.PrivateKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip39.MnemonicGenerator;
import io.github.novacrypto.bip39.SeedCalculator;
import io.github.novacrypto.bip39.Words;
import io.github.novacrypto.bip39.wordlists.English;
import io.github.novacrypto.bip44.AddressIndex;

import java.security.SecureRandom;

import static io.github.novacrypto.bip32.Index.hard;
import static io.github.novacrypto.bip44.BIP44.m;

public final class Main {

    public static void main(String[] args) {
        final String mnemonic = generateNewMnemonic(Words.TWELVE);
        System.out.println(mnemonic);

        final byte[] seed = new SeedCalculator().calculateSeed(mnemonic, "");

        PrivateKey root = PrivateKey.fromSeed(seed, Bitcoin.TEST_NET);

        String addressMethod1 = root
                .cKDpriv(hard(44)) //fixed
                .cKDpriv(hard(1)) //bitcoin testnet coin
                .cKDpriv(hard(0)) //account =1
                .cKDpriv(0) //external
                .cKDpriv(0) //first address
                .neuter().p2pkhAddress();

        String addressMethod2 = root
                .cKDpriv(hard(44)) //fixed
                .cKDpriv(hard(1)) //bitcoin testnet coin
                .cKDpriv(hard(0)) //account =1
                .neuter() //switch to public keys
                .cKDpub(0) //external
                .cKDpub(0) //first address
                .p2pkhAddress();

        String addressMethod3 = root
                .derive("m/44'/1'/0'/0/0")
                .neuter().p2pkhAddress();

        AddressIndex addressIndex = m()
                .purpose44()
                .coinType(1)
                .account(0)
                .external()
                .address(0);
        String addressMethod4 = root.derive(addressIndex, AddressIndex.DERIVATION)
                .neuter().p2pkhAddress();

        System.out.println(addressMethod1);
        System.out.println(addressMethod2);
        System.out.println(addressMethod3);
        System.out.println(addressMethod4);
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
