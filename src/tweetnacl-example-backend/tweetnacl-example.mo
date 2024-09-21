import NACL "mo:tweetnacl";
import Nat8 "mo:base/Nat8";
import Text "mo:base/Text";
import Option "mo:base/Option";
import Blob "mo:base/Blob";
import Bool "mo:base/Bool";
import Char "mo:base/Char";
import Array "mo:base/Array";
import HashMap "mo:base/HashMap";
import Iter "mo:base/Iter";
import Nat "mo:base/Nat";
import Nat32 "mo:base/Nat32";
import Hash "mo:base/Hash";
import Buffer "mo:base/Buffer";

actor {
    var bobSigningKeyPair = NACL.SIGN.keyPair(null);
    var aliceSigningKeyPair = NACL.SIGN.keyPair(null);
    var bobBoxKeyPair = NACL.BOX.keyPair(null);
    var aliceBoxKeyPair = NACL.BOX.keyPair(null);
    var nonce : [Nat8] = [];

    let convert = func (x : Text) : [Nat8] { Blob.toArray(Text.encodeUtf8(x)) };
    let revert = func (r : [Nat8]) : Text { Option.get(Text.decodeUtf8(Blob.fromArray(r)), "")};

    public shared func convertText(t :  Text) : async [Nat8] {
        let a : [Nat8] = [];
        ignore NACL.hash(a);
        convert(t);
    };

    private func getSigningKP(i : Nat) : {publicKey : [Nat8]; secretKey : [Nat8]} {
        switch (i) {
            case (1) bobSigningKeyPair;
            case (_) aliceSigningKeyPair;
        };
    };

    private func getBoxKP(i : Nat) : {publicKey : [Nat8]; secretKey : [Nat8]} {
        switch (i) {
            case (1) bobBoxKeyPair;
            case (_) aliceBoxKeyPair;
        };
    };

    public func getSigningKeyPair(i : Nat) : async {publicKey : Text; secretKey : Text} {
        let kp = getSigningKP(i);
        {publicKey = bytesToHex(kp.publicKey); secretKey = bytesToHex(kp.secretKey)};
    };

    public func getBoxKeyPair(i : Nat) : async {publicKey : Text; secretKey : Text} {
        let kp = getBoxKP(i);
        {publicKey = bytesToHex(kp.publicKey); secretKey = bytesToHex(kp.secretKey)};
    };



    public shared func sign(msg : Text, secretKey : Text) : async Text {
        let rs = NACL.SIGN.sign(convert(msg), hexToBytes(secretKey));
        bytesToHex(rs);
    };

    public shared func signVerify(msg : Text, publicKey : Text) : async (Text, Text) {
        let rs = NACL.SIGN.open(hexToBytes(msg), hexToBytes(publicKey));
        switch(rs) {
            case null ("", "");
            case (?r) (bytesToHex(r), revert(r));
        };
    };

    public shared func detached(msg : Text, secretKey : Text) : async Text {
        let signature = NACL.SIGN.DETACHED.detached(convert(msg), hexToBytes(secretKey));
        bytesToHex(signature);
    };

    public shared func detachedVerify(msg : Text, signature : Text, publicKey : Text) : async Bool {
        NACL.SIGN.DETACHED.verify(convert(msg), hexToBytes(signature), hexToBytes(publicKey));
    };

    public shared func box(msg : Text, pKey : Nat, sKey : Nat) : async Text {
        let rs = NACL.BOX.box(convert(msg), 
                                            nonce,
                                            getBoxKP(pKey).publicKey,
                                            getBoxKP(sKey).secretKey);
        bytesToHex(rs);
    };

    public shared func open(msg : Text, pKey : Nat, sKey : Nat) : async (Text, Text) {
        let rs = NACL.BOX.open(hexToBytes(msg), 
                                            nonce,
                                            getBoxKP(pKey).publicKey,
                                            getBoxKP(sKey).secretKey);
        switch(rs) {
            case null ("", "");
            case (?r) (bytesToHex(r), revert(r));
        };
    };

    public shared func makeKey(a : Nat, b : Nat) : async Text {
        let k = NACL.BOX.SECRET.before(getBoxKP(a).publicKey, getBoxKP(b).secretKey);
        bytesToHex(k);
    };

    public shared func secret_box(msg : Text, sharedKey : Text) : async Text {
        let rs = NACL.BOX.SECRET.box(convert(msg), 
                                            nonce,
                                            hexToBytes(sharedKey));
        bytesToHex(rs);
    };

    public shared func secret_box_open(msg : Text, sharedKey : Text) : async (Text, Text) {
        let rs = NACL.BOX.SECRET.open(hexToBytes(msg), 
                                            nonce,
                                            hexToBytes(sharedKey));
        switch(rs) {
            case null ("", "");
            case (?r) (bytesToHex(r), revert(r));
        };
    };

    public shared func genNonce() : async Text {
        nonce := NACL.randomBytes(NACL.BOX.NONCE_LENGTH);
        bytesToHex(nonce);
    };

    public shared func genSigningKeyPair(i : Nat) : async {publicKey : Text; secretKey : Text} {
        let kp = switch (i) {
            case (1) {
                bobSigningKeyPair := NACL.SIGN.keyPair(null);
                bobSigningKeyPair;
            };
            case (_) {
                aliceSigningKeyPair := NACL.SIGN.keyPair(null);
                aliceSigningKeyPair;
            };
        };
        {publicKey = bytesToHex(kp.publicKey); secretKey = bytesToHex(kp.secretKey)};
    };

    public shared func genBoxKeyPair(i : Nat) : async {publicKey : Text; secretKey : Text} {
        let kp = switch (i) {
            case (1) {
                bobBoxKeyPair := NACL.BOX.keyPair(null);
                bobBoxKeyPair;
            };
            case (_) {
                aliceBoxKeyPair := NACL.BOX.keyPair(null);
                aliceBoxKeyPair;
            };
        };
        {publicKey = bytesToHex(kp.publicKey); secretKey = bytesToHex(kp.secretKey)};
    };

    private func getHexes() : [Text] {
        let symbols = [
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ];
        let base : Nat8 = 0x10;
        func nat8ToText(u8: Nat8) : Text {
            let c1 = symbols[Nat8.toNat((u8/base))];
            let c2 = symbols[Nat8.toNat((u8%base))];
            return Char.toText(c1) # Char.toText(c2);
        };
        let array : [Text] = Array.tabulate<Text>(256, func i = nat8ToText(Nat8.fromNat(i)));
        return array;
    };

    private func bytesToHex(uint8a: [Nat8]): Text {
        // pre-caching improves the speed 6x
        let hexes = getHexes();
        let hex = Array.foldRight<Nat8, Text>(uint8a, "", 
                                            func(x, acc) = hexes[Nat8.toNat(x)] # acc);
        return hex;
    };

    // Caching slows it down 2-3x
    private func hexToBytes(hex: Text): [Nat8] {
        var map = HashMap.HashMap<Nat, Nat8>(1, Nat.equal, Hash.hash);
        // '0': 48 -> 0; '9': 57 -> 9
        for (num in Iter.range(48, 57)) {
            map.put(num, Nat8.fromNat(num-48));
        };
        // 'a': 97 -> 10; 'f': 102 -> 15
        for (lowcase in Iter.range(97, 102)) {
            map.put(lowcase, Nat8.fromNat(lowcase-97+10));
        };
        // 'A': 65 -> 10; 'F': 70 -> 15
        for (uppercase in Iter.range(65, 70)) {
            map.put(uppercase, Nat8.fromNat(uppercase-65+10));
        };
        let p = Iter.toArray(Iter.map(Text.toIter(hex),
                            func (x: Char) : Nat { Nat32.toNat(Char.toNat32(x)) }));
        var res : [var Nat8] = [var];       
        for (i in Iter.range(0, p.size() / 2 - 1)) {            
            let a = Option.unwrap<Nat8>(map.get(p[i*2]));
            let b = Option.unwrap<Nat8>(map.get(p[i*2 + 1]));
            let c = 16*a + b;
            res := Array.thaw(Array.append(Array.freeze(res), Array.make(c)));
        };
        let result = Array.freeze(res);
        return result;
    };
};