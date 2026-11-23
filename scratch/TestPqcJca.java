import java.security.*;
import java.security.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public class TestPqcJca {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        // Test ML-DSA-65 KeyFactory and Signature
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("ML-DSA-65", "BC");
        KeyPair dsaKp = dsaKpg.generateKeyPair();
        byte[] dsaPubEncoded = dsaKp.getPublic().getEncoded();
        System.out.println("ML-DSA-65 X509 encoded length: " + dsaPubEncoded.length);

        KeyFactory dsaKf = KeyFactory.getInstance("ML-DSA-65", "BC");
        PublicKey dsaPubDecoded = dsaKf.generatePublic(new X509EncodedKeySpec(dsaPubEncoded));
        System.out.println("ML-DSA-65 decoded successfully: " + (dsaPubDecoded != null));

        Signature sig = Signature.getInstance("ML-DSA-65", "BC");
        sig.initSign(dsaKp.getPrivate());
        sig.update(new byte[]{1,2,3});
        byte[] signature = sig.sign();
        System.out.println("ML-DSA-65 signature length: " + signature.length);

        sig.initVerify(dsaPubDecoded);
        sig.update(new byte[]{1,2,3});
        boolean verified = sig.verify(signature);
        System.out.println("ML-DSA-65 verified: " + verified);

        // Test ML-KEM-768 KeyFactory
        KeyPairGenerator kemKpg = KeyPairGenerator.getInstance("ML-KEM-768", "BC");
        KeyPair kemKp = kemKpg.generateKeyPair();
        byte[] kemPubEncoded = kemKp.getPublic().getEncoded();
        System.out.println("ML-KEM-768 X509 encoded length: " + kemPubEncoded.length);

        KeyFactory kemKf = KeyFactory.getInstance("ML-KEM-768", "BC");
        PublicKey kemPubDecoded = kemKf.generatePublic(new X509EncodedKeySpec(kemPubEncoded));
        System.out.println("ML-KEM-768 decoded successfully: " + (kemPubDecoded != null));
    }
}
