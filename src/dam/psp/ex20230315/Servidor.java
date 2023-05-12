package dam.psp.ex20230315;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Servidor extends Thread {
	
	static KeyStore ks;
	
	static {
		try {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
//			ks.load(Servidor.class.getResourceAsStream("/keystore.p12"), "practicas".toCharArray());
			ks.load(null);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	
	public static void main(String[] args) throws IOException {
		ExecutorService executor = Executors.newFixedThreadPool(100);
		ServerSocket sSocket = new ServerSocket(9000);
		System.out.println("Servidor  puerto 9000");
		while (true) {
			Socket sCliente = sSocket.accept();
			sCliente.setSoTimeout(5000);
			executor.execute(new Servicio(sCliente));
		}
	}
}