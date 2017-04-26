package br.ufsm.politecnico.csi.seguranca;

import com.sun.org.apache.xml.internal.security.algorithms.MessageDigestAlgorithm;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.beans.XMLDecoder;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

/**
 * Created by Diovane on 25/04/2017.
 */
public class Bob {
    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, InvalidKeySpecException {

        System.out.println("Selecionando arquivo...");
        JFileChooser chooserArquivo = new JFileChooser();
        chooserArquivo.setDialogTitle("Selecionar o arquivo a ser enviado...");
        int escolha = chooserArquivo.showOpenDialog(new JFrame());
        if (escolha != JFileChooser.APPROVE_OPTION) {
            return;
        }
        System.out.println("Arquivo selecionado");


        System.out.println("Lendo arquivo selecionado...");
        File arquivo = new File(chooserArquivo.getSelectedFile().getAbsolutePath());
        FileInputStream fin = new FileInputStream(arquivo);
        byte[] barquivo = new byte[(int) fin.getChannel().size()];
        fin.read(barquivo);
        System.out.println("Arquivo lido");


        System.out.println("Lendo certificado de Bob...");
        File certificadoBob = new File("Diovane (Bob)_cert.xml");
        FileInputStream finBob = new FileInputStream(certificadoBob);
        byte[] b_certificadoBob = new byte[(int) finBob.getChannel().size()];
        finBob.read(b_certificadoBob);
        System.out.println("Certificado lido");


        System.out.println("Lendo a chave privada de Bob...");
        File privadaBob = new File("chavePrivBob.txt");
        FileInputStream finChaPrivaBob = new FileInputStream(privadaBob);
        byte[] b_privateBob = new byte[(int) finChaPrivaBob.getChannel().size()];
        finChaPrivaBob.read(b_privateBob);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKeyBob = kf.generatePrivate(new PKCS8EncodedKeySpec(b_privateBob));
        System.out.println("Chave privada de Bob lida");


        System.out.println("Lendo chave publica da CA...");
        File publicaCA = new File("pub.key");
        FileInputStream finChaPubCA = new FileInputStream(publicaCA);
        byte[] b_publicaCA = new byte[(int) finChaPubCA.getChannel().size()];
        finChaPubCA.read(b_publicaCA);
        PublicKey publicKeyCA = kf.generatePublic(new X509EncodedKeySpec(b_publicaCA));
        System.out.println("Chave publica CA lida");


        System.out.println("Conectando com Alice...");
        Socket s = new Socket("localhost", 3333);
        System.out.println("Conectou a Alice.");


        System.out.println("Recebendo certificado de Alice...");
        ObjectInputStream in = new ObjectInputStream(s.getInputStream());
        ObjetoTroca obj = (ObjetoTroca) in.readObject();
        System.out.println("7. Recebeu certificado.");


        System.out.println("Convertendo certificado em XML...");
        FileOutputStream File = new FileOutputStream("ObjetoCertificadoAlice.xml");
        File.write(obj.getCertificado());
        File.close();
        System.out.println("Converteu Arquivo recebido de ALice para XML");


        System.out.println("Lendo certificado XML de Alice e pegando dados...");
        FileInputStream fis = new FileInputStream("ObjetoCertificadoAlice.xml");
        BufferedInputStream bis = new BufferedInputStream(fis);
        XMLDecoder xmlDecoder = new XMLDecoder(bis);
        Certificado  ObjetoCertificadoAlice = (Certificado) xmlDecoder.readObject();
        System.out.println("Leu dados do certificado de Alice ");


        System.out.println("Verificando a data de validade do certificado de Alice...");
        SimpleDateFormat SDF = new SimpleDateFormat("dd/MM/yyyy");
        Date dataHoje = new Date();
        if(!ObjetoCertificadoAlice.getValidoAte().after(dataHoje)) {
            System.out.println("Certificado vencido - Conexão encerrada!!!");
            s.close();
            System.exit(0);
        }
        System.out.println("Certificado dentro do prazo de validade");


        System.out.println("Descriptografando assinatura do certificado de Alice para pegar hash...");
        Cipher cipherHashAssinatura = Cipher.getInstance("RSA");
        cipherHashAssinatura.init(Cipher.DECRYPT_MODE,publicKeyCA);
        byte[] arquivoHashAssinaturaAlice = cipherHashAssinatura.doFinal(ObjetoCertificadoAlice.getAssinatura());
        System.out.println("Descriptografou a Assinatura(Hash) de Alice.");


        System.out.println("Criando hash com nome + data de validade + chave publica do certificado de Alice...");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        bout.write(ObjetoCertificadoAlice.getNome().getBytes("ISO-8859-1"));
        bout.write("30/06/2017".getBytes("ISO-8859-1"));
        bout.write(ObjetoCertificadoAlice.getChavePublica());
        byte [] hash = md.digest(bout.toByteArray());
        System.out.println("Hash criado");


        System.out.println("Comparando hashs para validar certificado");
        if(!Arrays.equals(hash,arquivoHashAssinaturaAlice))
        {
            System.out.println("Certificado de Alice é inválido - Conexão encerrada!!!");
            s.close();
            System.exit(0);
        }
        System.out.println("Certificado De Alice é válido (Autenticidade Garantida)");


        System.out.println("Criando chave de sessao...");
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        SecretKey aeskey_sessao = kgen.generateKey();
        byte[] chave_sessao_Bob = aeskey_sessao.getEncoded();
        System.out.println("Chave de sessao criada");


        System.out.println("Criptografando arquivo com chave de sessao...");
        Cipher cipher_arquivo = Cipher.getInstance("AES");
        cipher_arquivo.init(Cipher.ENCRYPT_MODE, aeskey_sessao);
        byte[] arquivo_cripto_Bob = cipher_arquivo.doFinal(barquivo);
        System.out.println("Arquivo criptografado");


        System.out.println("Criptografando chave de sessao com chave publica Alice que esta no certificado...");
        PublicKey publicKeyAlice = kf.generatePublic(new X509EncodedKeySpec(ObjetoCertificadoAlice.getChavePublica()));
        Cipher cipher_sessao = Cipher.getInstance("RSA");
        cipher_sessao.init(Cipher.ENCRYPT_MODE,publicKeyAlice);
        byte[] chave_sessao_cripto_Bob = cipher_sessao.doFinal(chave_sessao_Bob);
        System.out.println("Chave de sessao criptografada");


        System.out.println("Criando hash do arquivo para criptografar e enviar...");
        md = MessageDigest.getInstance("SHA-256");
        byte[] arquivoHash = md.digest(barquivo);
        System.out.println("Hash criado");


        System.out.println("Criptografando hash comchave privada de Bob...");
        Cipher cipher_hash = Cipher.getInstance("RSA");
        cipher_hash.init(Cipher.ENCRYPT_MODE,privateKeyBob );
        byte[] hash_cripto_bob = cipher_hash.doFinal(arquivoHash);
        System.out.println("Hash criptografado");


        System.out.println("Enviando dados para Alice...");
        //ver problema de conexão aqui
        ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
        ObjetoTroca objEnvio = new ObjetoTroca();
        objEnvio.setChaveSessao(chave_sessao_cripto_Bob);
        objEnvio.setArquivo(arquivo_cripto_Bob);
        objEnvio.setNomeArquivo(chooserArquivo.getSelectedFile().getName());
        objEnvio.setAssinatura(hash_cripto_bob);
        objEnvio.setCertificado(b_certificadoBob);
        out.writeObject(objEnvio);
        out.close();
        System.out.println("Dados enviados");


        System.out.println("Conexão fechada.");
        s.close();
    }
}
