package br.ufsm.politecnico.csi.seguranca;

import java.io.Serializable;
import java.util.Date;

/**
 * Created by Diovane on 25/04/2017.
 */
public class Certificado implements Serializable {
    private String nome;
    private String endereco;
    private Date validoAte;
    private byte[] chavePublica;
    private byte[] assinatura;
    private String certificador;
    private Date dataCertificacao;

    public String getNome() {
        return nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public String getEndereco() {
        return endereco;
    }

    public void setEndereco(String endereco) {
        this.endereco = endereco;
    }

    public Date getValidoAte() {
        return validoAte;
    }

    public void setValidoAte(Date validoAte) {
        this.validoAte = validoAte;
    }

    public byte[] getChavePublica() {
        return chavePublica;
    }

    public void setChavePublica(byte[] chavePublica) {
        this.chavePublica = chavePublica;
    }

    public byte[] getAssinatura() {
        return assinatura;
    }

    public void setAssinatura(byte[] assinatura) {
        this.assinatura = assinatura;
    }

    public String getCertificador() {
        return certificador;
    }

    public void setCertificador(String certificador) {
        this.certificador = certificador;
    }

    public Date getDataCertificacao() {
        return dataCertificacao;
    }

    public void setDataCertificacao(Date dataCertificacao) {
        this.dataCertificacao = dataCertificacao;
    }

    public boolean validaDataCertificado(Date dataTeste){
        if(dataTeste.before(this.validoAte)){
            return true;
        }else{
            return false;
        }
    }

}
