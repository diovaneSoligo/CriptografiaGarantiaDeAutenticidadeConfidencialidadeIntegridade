package br.ufsm.politecnico.csi.seguranca;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.beans.XMLDecoder;
import java.io.*;
import java.net.ServerSocket;
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
public class Alice {
    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, InvalidKeySpecException {

        System.out.println("Abrindo socket");
        ServerSocket ss = new ServerSocket(3333);
        System.out.println("Socket aberto");

        System.out.println("Lendo certificado");
        File arquivo = new File("Diovane (Alice)_cert.xml");
        FileInputStream fin = new FileInputStream(arquivo);
        byte[] B_XML = new byte[(int) fin.getChannel().size()];
        fin.read(B_XML);
        System.out.println("Leu certificado");

        while (true) {
            System.out.println("Aguardando conexões...");
            Socket s = ss.accept();
            System.out.println("Cliente conectado.");


            System.out.println("Enviando certificado de Alice para cliente Bob...");
            ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
            ObjetoTroca certificado = new ObjetoTroca();
            certificado.setCertificado(B_XML);
            out.writeObject(certificado);
            //out.close(); //se fechar o objectOutput encerra a sessão
            System.out.println("Certificado enviado");


            System.out.println("Alice recebendo dados do Bob...");
            //ver problema de tempo aqui
            ObjectInputStream in = new ObjectInputStream(s.getInputStream());
            ObjetoTroca objetoBob = (ObjetoTroca) in.readObject();
            System.out.println("Dados recebidos");


            System.out.println("Convertendo certificado de Bob em XML...");
            FileOutputStream File = new FileOutputStream("ObjetoCertificadoBob.xml");
            File.write(objetoBob.getCertificado());
            File.close();
            System.out.println("Converteu objetoBob.getCertificado() recebido de Bob para XML");


            System.out.println("Lendo certificado Bob .xml e seus dados...");
            FileInputStream fis = new FileInputStream("ObjetoCertificadoBob.xml");
            BufferedInputStream bis = new BufferedInputStream(fis);
            XMLDecoder xmlDecoder = new XMLDecoder(bis);
            Certificado  ObjetoCertificadoBob = (Certificado) xmlDecoder.readObject();
            System.out.println("Leu dados do certificado");


            System.out.println("Verificando data de validade do certificado de Bob...");
            SimpleDateFormat SDF = new SimpleDateFormat("dd/MM/yyyy");
            Date dataHoje = new Date();
            if(!ObjetoCertificadoBob.getValidoAte().after(dataHoje)) {
                System.out.println("Certificado vencido - Conexão encerrada!!!");
                s.close();
                System.exit(0);
            }
            System.out.println("Certificado dentro do prazo de validade");


            System.out.println("Lendo chave pública da CA...");
            File publicaCA = new File("pub.key");
            FileInputStream finChaPubCA = new FileInputStream(publicaCA);
            byte[] b_publicaCA = new byte[(int) finChaPubCA.getChannel().size()];
            finChaPubCA.read(b_publicaCA);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKeyCA = kf.generatePublic(new X509EncodedKeySpec(b_publicaCA));
            System.out.println("chave puclica CA lida - > publicKeyCA");


            System.out.println("Descriptografando o hash da assinatura do Bob");
            Cipher cipherHashAssinatura = Cipher.getInstance("RSA");
            cipherHashAssinatura.init(Cipher.DECRYPT_MODE,publicKeyCA);
            byte[] arquivoHashAssinaturaBob = cipherHashAssinatura.doFinal(ObjetoCertificadoBob.getAssinatura());
            System.out.println("Descriptografou a Assinatura(Hash) de Bob.");


            System.out.println("Criando hash com nome + data de validade + chave publica do certificado de Bob...");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            bout.write(ObjetoCertificadoBob.getNome().getBytes("ISO-8859-1"));
            bout.write("30/06/2017".getBytes("ISO-8859-1"));
            bout.write(ObjetoCertificadoBob.getChavePublica());
            byte [] hash = md.digest(bout.toByteArray());
            System.out.println("Hash criado");


            System.out.println("Comparando Hashs... ");
            if(!Arrays.equals(hash,arquivoHashAssinaturaBob))
            {
                System.out.println("Certificado de Bob é inválido - Conexão encerrada!!!");
                s.close();
                System.exit(0);
            }
            System.out.println("Certificado De Bob é válido (Autenticidade Garantida)");


            System.out.println("Lendo chave privada de Alice...");
            File privadaAlice = new File("chavePrivAlice.txt");
            FileInputStream finChaPrivaAlice = new FileInputStream(privadaAlice);
            byte[] b_privateAlice = new byte[(int) finChaPrivaAlice.getChannel().size()];
            finChaPrivaAlice.read(b_privateAlice);
            kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKeyAlice = kf.generatePrivate(new PKCS8EncodedKeySpec(b_privateAlice));
            System.out.println("Leu Chave Privada de Alice");


            System.out.println("Descriptografando chave de sessão de Bob com chave privada de Alice...");
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,privateKeyAlice);
            byte[] c_sessao= cipher.doFinal( objetoBob.getChaveSessao());
            SecretKeySpec ks = new SecretKeySpec(c_sessao,"AES");
            System.out.println(" Chave de sessao de Bob descriptografada");


            System.out.println("Descriptografando arquivo com chave de sessao do Bob...");
            Cipher cipher_arquivo = Cipher.getInstance("AES");
            cipher_arquivo.init(Cipher.DECRYPT_MODE,ks);
            byte[] b_arquivo = cipher_arquivo.doFinal(objetoBob.getArquivo());
            System.out.println("Arquivo descriptografado");


            System.out.println("Gerando hash do arquivo descriptografado...");
            md = MessageDigest.getInstance("SHA-256");
            byte[] arquivoHash = md.digest(b_arquivo);
            System.out.println("Hash do Arquivo gerado");


            System.out.println("Descriptografando assinatura com chave pub do certificado de Bob para pegar o hash do arquivo");
            PublicKey publicKeyBob = kf.generatePublic(new X509EncodedKeySpec(ObjetoCertificadoBob.getChavePublica()));
            Cipher cipherHASH = Cipher.getInstance("RSA");
            cipherHASH.init(Cipher.DECRYPT_MODE,publicKeyBob);
            byte[] arquivoHashBob = cipherHASH.doFinal(objetoBob.getAssinatura());
            System.out.println("Assinatura descriptografada, hash pronto");


            System.out.println("Verificando integridade do arquivo...");
            if(!Arrays.equals(arquivoHash,arquivoHashBob))
            {
                System.out.println("Arquivo não válido - Conexão encerrada!!!");
                s.close();
                System.exit(0);
            }
            System.out.println("Arquivo recebido válido (integridade garantida)");


            System.out.println("Gravando arquivo em disco...");
            File saida = new File(objetoBob.getNomeArquivo());
            OutputStream fout = new FileOutputStream(saida);
            fout.write(b_arquivo);
            fout.close();
            System.out.println("Arquivo gravado");


            System.out.println("Conexão fechada.\n\n");
            s.close();
        }
    }
}
