package com.localproxy;

import com.sun.net.httpserver.*;
import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

public class LocalHttpsProxy {

    static final int HTTPS_PORT = 9443;
    static volatile int targetPort = 8080;
    static volatile String localIp = "127.0.0.1";
    static final AtomicLong totalRequests = new AtomicLong(0);
    static final AtomicLong successCount = new AtomicLong(0);
    static final AtomicLong errorCount = new AtomicLong(0);
    static final List<String> requestLog = Collections.synchronizedList(new ArrayList<>());
    static volatile boolean running = false;
    static HttpServer adminServer;
    static HttpsServer httpsServer;

    public static void main(String[] args) throws Exception {
        System.out.println(banner());

        // Detect local IP
        localIp = detectLocalIp();
        System.out.println("  Detected local IP: " + localIp);

        // Ask for target port
        System.out.print("\n  Enter the port of your application (default 8080): ");
        Scanner scanner = new Scanner(System.in);
        String input = scanner.nextLine().trim();
        if (!input.isEmpty()) {
            try {
                targetPort = Integer.parseInt(input);
            } catch (NumberFormatException e) {
                System.out.println("  Invalid port, using 8080");
            }
        }

        // Generate self-signed certificate
        System.out.println("\n  Generating self-signed certificate for " + localIp + "...");
        KeyStore keyStore = CertGenerator.generateKeyStore(localIp);
        System.out.println("  Certificate generated!");

        // Start admin UI server (HTTP on port 9444)
        startAdminServer(keyStore);

        // Start HTTPS proxy
        startHttpsProxy(keyStore);

        running = true;

        System.out.println("\n" + separator());
        System.out.println("  HTTPS Proxy is RUNNING!");
        System.out.println(separator());
        System.out.printf("  Proxy URL   : https://%s:%d%n", localIp, HTTPS_PORT);
        System.out.printf("  Target      : http://%s:%d%n", localIp, targetPort);
        System.out.printf("  Admin UI    : http://localhost:9444%n");
        System.out.println(separator());
        System.out.println("\n  NOTE: Browsers will show a certificate warning.");
        System.out.println("        Click 'Advanced' -> 'Proceed' to accept.");
        System.out.println("        Or import the certificate from Admin UI.");
        System.out.println("\n  Press CTRL+C to stop.\n");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n  Shutting down proxy...");
            if (httpsServer != null) httpsServer.stop(0);
            if (adminServer != null) adminServer.stop(0);
            System.out.println("  Bye!");
        }));

        Thread.currentThread().join();
    }

    static void startHttpsProxy(KeyStore keyStore) throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "password".toCharArray());
        sslContext.init(kmf.getKeyManagers(), null, null);

        httpsServer = HttpsServer.create(new InetSocketAddress("0.0.0.0", HTTPS_PORT), 0);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            public void configure(HttpsParameters params) {
                SSLParameters sp = sslContext.getDefaultSSLParameters();
                params.setSSLParameters(sp);
            }
        });

        httpsServer.createContext("/", new ProxyHandler());
        httpsServer.setExecutor(Executors.newFixedThreadPool(20));
        httpsServer.start();
    }

    static void startAdminServer(KeyStore keyStore) throws Exception {
        adminServer = HttpServer.create(new InetSocketAddress("localhost", 9444), 0);
        adminServer.createContext("/", new AdminHandler(keyStore));
        adminServer.createContext("/api/stats", new StatsApiHandler());
        adminServer.createContext("/api/config", new ConfigApiHandler());
        adminServer.setExecutor(Executors.newFixedThreadPool(4));
        adminServer.start();
    }

    static List<String> detectAllIps() {
        record Candidate(String ip, int priority) {}
        List<Candidate> list = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                if (ni.isLoopback() || !ni.isUp()) continue;
                String name        = ni.getName().toLowerCase();
                String displayName = ni.getDisplayName().toLowerCase();
                boolean isVirtual =
                    displayName.contains("virtual") ||
                    displayName.contains("hyper-v") ||
                    displayName.contains("vethernet") ||
                    displayName.contains("wsl") ||
                    displayName.contains("docker") ||
                    displayName.contains("vmware") ||
                    displayName.contains("virtualbox") ||
                    name.startsWith("veth") ||
                    name.startsWith("docker") ||
                    name.startsWith("br-") ||
                    name.startsWith("tun") ||
                    name.startsWith("tap");
                boolean isWifi =
                    name.contains("wlan") || name.contains("wifi") ||
                    displayName.contains("wi-fi") || displayName.contains("wifi") ||
                    displayName.contains("wireless");
                Enumeration<InetAddress> addresses = ni.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (!(addr instanceof Inet4Address) || addr.isLoopbackAddress()) continue;
                    String ip = addr.getHostAddress();
                    int priority;
                    if (ip.startsWith("192.168.")) {
                        priority = isVirtual ? 20 : (isWifi ? 1 : 2);
                    } else if (ip.startsWith("10.")) {
                        priority = isVirtual ? 21 : (isWifi ? 3 : 4);
                    } else if (ip.startsWith("172.")) {
                        if (isVirtual) continue;
                        priority = isWifi ? 5 : 10;
                    } else {
                        continue;
                    }
                    list.add(new Candidate(ip, priority));
                }
            }
        } catch (Exception ignored) {}
        list.sort(Comparator.comparingInt(Candidate::priority));
        List<String> result = new ArrayList<>();
        for (Candidate c : list) result.add(c.ip);
        return result;
    }

    static String detectLocalIp() {
        // Collect all candidate IPs with priority scores.
        // Priority 1 (best)  : 192.168.x.x on a WiFi/WLAN adapter (real LAN)
        // Priority 2         : 192.168.x.x on any adapter
        // Priority 3         : 10.x.x.x on a WiFi/WLAN adapter
        // Priority 4         : 10.x.x.x on any adapter
        // Priority 5         : 172.16-31.x.x ONLY on WiFi/WLAN (avoid Hyper-V / Docker)
        // Fallback            : 127.0.0.1
        //
        // Virtual/tunnel adapters (Hyper-V, WSL, VirtualBox, Docker, VPN tun/tap)
        // are explicitly skipped so that the real Wi-Fi adapter wins.
        String best = null;
        int bestPriority = Integer.MAX_VALUE;

        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                if (ni.isLoopback() || !ni.isUp()) continue;

                String name = ni.getName().toLowerCase();           // e.g. eth0, wlan0
                String displayName = ni.getDisplayName().toLowerCase(); // e.g. wi-fi, vethernet

                // Skip known virtual adapters
                boolean isVirtual =
                    displayName.contains("virtual") ||
                    displayName.contains("hyper-v") ||
                    displayName.contains("vethernet") ||
                    displayName.contains("wsl") ||
                    displayName.contains("docker") ||
                    displayName.contains("vmware") ||
                    displayName.contains("virtualbox") ||
                    name.startsWith("veth") ||
                    name.startsWith("docker") ||
                    name.startsWith("br-") ||
                    name.startsWith("tun") ||
                    name.startsWith("tap");

                boolean isWifi =
                    name.contains("wlan") ||
                    name.contains("wifi") ||
                    name.contains("wi-fi") ||
                    name.contains("wireless") ||
                    displayName.contains("wi-fi") ||
                    displayName.contains("wifi") ||
                    displayName.contains("wireless");

                Enumeration<InetAddress> addresses = ni.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (!(addr instanceof Inet4Address) || addr.isLoopbackAddress()) continue;
                    String ip = addr.getHostAddress();

                    int priority = Integer.MAX_VALUE;

                    if (ip.startsWith("192.168.")) {
                        priority = isVirtual ? 20 : (isWifi ? 1 : 2);
                    } else if (ip.startsWith("10.")) {
                        priority = isVirtual ? 21 : (isWifi ? 3 : 4);
                    } else if (ip.startsWith("172.")) {
                        // 172.16.0.0/12 — skip virtual ones entirely
                        if (isVirtual) continue;
                        priority = isWifi ? 5 : 10;
                    }

                    if (priority < bestPriority) {
                        bestPriority = priority;
                        best = ip;
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }

        return best != null ? best : "127.0.0.1";
    }

    static void logRequest(String method, String path, int status, long ms) {
        String time = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        String entry = String.format("{\"time\":\"%s\",\"method\":\"%s\",\"path\":\"%s\",\"status\":%d,\"ms\":%d}",
                time, method, path, status, ms);
        requestLog.add(0, entry);
        if (requestLog.size() > 100) requestLog.remove(requestLog.size() - 1);
    }

    static String banner() {
        return """
                
                ╔═══════════════════════════════════════════════╗
                ║         LOCAL HTTPS PROXY  v1.0               ║
                ║     Camera • Location • Secure APIs           ║
                ╚═══════════════════════════════════════════════╝
                """;
    }

    static String separator() {
        return "  ─────────────────────────────────────────────";
    }

    // ── Proxy Handler ──────────────────────────────────────────────────────────

    static class ProxyHandler implements HttpHandler {
        final HttpClient client;

        ProxyHandler() throws Exception {
            SSLContext trustAll = SSLContext.getInstance("TLS");
            trustAll.init(null, new TrustManager[]{new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
            }}, null);

            client = HttpClient.newBuilder()
                    .sslContext(trustAll)
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            long start = System.currentTimeMillis();
            totalRequests.incrementAndGet();
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().toString();

            try {
                String targetUrl = "http://" + localIp + ":" + targetPort + path;
                byte[] requestBody = exchange.getRequestBody().readAllBytes();

                HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                        .uri(URI.create(targetUrl))
                        .timeout(Duration.ofSeconds(30));

                // Copy headers (skip host/connection)
                exchange.getRequestHeaders().forEach((key, values) -> {
                    if (!key.equalsIgnoreCase("Host") && !key.equalsIgnoreCase("Connection")
                            && !key.equalsIgnoreCase("Keep-Alive") && !key.equalsIgnoreCase("Transfer-Encoding")) {
                        values.forEach(v -> {
                            try { reqBuilder.header(key, v); } catch (Exception ignored) {}
                        });
                    }
                });

                // Add forwarding headers
                String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();
                try {
                    reqBuilder.header("X-Forwarded-For", clientIp);
                    reqBuilder.header("X-Forwarded-Proto", "https");
                    reqBuilder.header("X-Real-IP", clientIp);
                } catch (Exception ignored) {}

                if (requestBody.length > 0) {
                    reqBuilder.method(method, HttpRequest.BodyPublishers.ofByteArray(requestBody));
                } else if (method.equals("POST") || method.equals("PUT") || method.equals("PATCH")) {
                    reqBuilder.method(method, HttpRequest.BodyPublishers.noBody());
                } else {
                    reqBuilder.method(method, HttpRequest.BodyPublishers.noBody());
                }

                HttpResponse<byte[]> response = client.send(reqBuilder.build(),
                        HttpResponse.BodyHandlers.ofByteArray());

                // Forward response headers
                response.headers().map().forEach((key, values) -> {
                    if (!key.equalsIgnoreCase(":status") && !key.equalsIgnoreCase("Transfer-Encoding")) {
                        values.forEach(v -> exchange.getResponseHeaders().add(key, v));
                    }
                });

                // CORS for local dev
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH");
                exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "*");

                byte[] body = response.body();
                exchange.sendResponseHeaders(response.statusCode(), body.length == 0 ? -1 : body.length);
                if (body.length > 0) {
                    exchange.getResponseBody().write(body);
                }
                exchange.getResponseBody().close();

                long ms = System.currentTimeMillis() - start;
                successCount.incrementAndGet();
                logRequest(method, path, response.statusCode(), ms);

            } catch (Exception e) {
                errorCount.incrementAndGet();
                long ms = System.currentTimeMillis() - start;
                logRequest(method, path, 502, ms);

                String msg = "502 Bad Gateway\n\nCould not connect to " + localIp + ":" + targetPort
                        + "\n\nMake sure your Spring Boot app is running on port " + targetPort
                        + "\n\nError: " + e.getMessage();
                byte[] bytes = msg.getBytes();
                exchange.sendResponseHeaders(502, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.getResponseBody().close();
            }
        }
    }

    // ── Stats API ──────────────────────────────────────────────────────────────

    static class StatsApiHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String logs = String.join(",", requestLog.subList(0, Math.min(20, requestLog.size())));
            String json = String.format(
                    "{\"total\":%d,\"success\":%d,\"errors\":%d,\"targetPort\":%d,\"localIp\":\"%s\",\"httpsPort\":%d,\"running\":%b,\"logs\":[%s]}",
                    totalRequests.get(), successCount.get(), errorCount.get(),
                    targetPort, localIp, HTTPS_PORT, running, logs);

            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            byte[] bytes = json.getBytes();
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.getResponseBody().close();
        }
    }

    // ── Config API ─────────────────────────────────────────────────────────────

    static class ConfigApiHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equals("POST")) {
                String body = new String(exchange.getRequestBody().readAllBytes());
                // Simple parse: {"port":XXXX}
                try {
                    String portStr = body.replaceAll(".*\"port\"\\s*:\\s*(\\d+).*", "$1");
                    int newPort = Integer.parseInt(portStr.trim());
                    targetPort = newPort;
                    System.out.println("  Target port changed to: " + newPort);
                    String resp = "{\"ok\":true,\"port\":" + newPort + "}";
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    byte[] bytes = resp.getBytes();
                    exchange.sendResponseHeaders(200, bytes.length);
                    exchange.getResponseBody().write(bytes);
                } catch (Exception e) {
                    exchange.sendResponseHeaders(400, 0);
                }
            } else {
                exchange.sendResponseHeaders(405, 0);
            }
            exchange.getResponseBody().close();
        }
    }

    // ── Admin UI ───────────────────────────────────────────────────────────────

    static class AdminHandler implements HttpHandler {
        final byte[] certDer;

        AdminHandler(KeyStore keyStore) throws Exception {
            certDer = keyStore.getCertificate("proxy").getEncoded();
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();

            if (path.equals("/cert")) {
                exchange.getResponseHeaders().set("Content-Type", "application/x-x509-ca-cert");
                exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=local-https-proxy.crt");
                exchange.sendResponseHeaders(200, certDer.length);
                exchange.getResponseBody().write(certDer);
                exchange.getResponseBody().close();
                return;
            }

            String html = buildAdminHtml();
            byte[] bytes = html.getBytes();
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.getResponseBody().close();
        }

        String buildAdminHtml() {
            return """
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Local HTTPS Proxy</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0a0f;
    --surface: #111118;
    --card: #16161f;
    --border: #2a2a3a;
    --accent: #00ff9d;
    --accent2: #7c3aed;
    --accent3: #f59e0b;
    --text: #e8e8f0;
    --muted: #6b6b80;
    --danger: #ff4757;
    --success: #00ff9d;
    --mono: 'JetBrains Mono', monospace;
    --sans: 'Syne', sans-serif;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    background-image:
      radial-gradient(ellipse at 10% 20%, rgba(124,58,237,0.08) 0%, transparent 50%),
      radial-gradient(ellipse at 90% 80%, rgba(0,255,157,0.06) 0%, transparent 50%);
  }
  header {
    border-bottom: 1px solid var(--border);
    padding: 18px 32px;
    display: flex;
    align-items: center;
    gap: 16px;
    background: rgba(17,17,24,0.8);
    backdrop-filter: blur(12px);
    position: sticky;
    top: 0;
    z-index: 10;
  }
  .logo {
    width: 36px; height: 36px;
    background: linear-gradient(135deg, var(--accent2), var(--accent));
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 18px;
  }
  .logo-text { font-size: 18px; font-weight: 800; letter-spacing: -0.5px; }
  .logo-text span { color: var(--accent); }
  .status-pill {
    margin-left: auto;
    padding: 4px 14px;
    border-radius: 20px;
    font-family: var(--mono);
    font-size: 12px;
    font-weight: 600;
    background: rgba(0,255,157,0.1);
    color: var(--accent);
    border: 1px solid rgba(0,255,157,0.3);
    display: flex; align-items: center; gap: 6px;
  }
  .dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 8px var(--accent);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.5; transform: scale(0.8); }
  }
  main { max-width: 900px; margin: 0 auto; padding: 32px 24px; }

  .hero {
    text-align: center;
    padding: 40px 0 32px;
  }
  .hero h1 {
    font-size: 42px; font-weight: 800;
    letter-spacing: -2px;
    line-height: 1.1;
    background: linear-gradient(135deg, #fff 30%, var(--accent));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 8px;
  }
  .hero p { color: var(--muted); font-size: 15px; }

  .url-box {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 20px 24px;
    margin: 24px 0;
    display: flex;
    align-items: center;
    gap: 16px;
    position: relative;
    overflow: hidden;
  }
  .url-box::before {
    content: '';
    position: absolute;
    inset: 0;
    background: linear-gradient(90deg, rgba(0,255,157,0.04), transparent);
    pointer-events: none;
  }
  .url-label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--muted);
    font-family: var(--mono);
    white-space: nowrap;
  }
  .url-value {
    font-family: var(--mono);
    font-size: 20px;
    font-weight: 700;
    color: var(--accent);
    flex: 1;
    word-break: break-all;
  }
  .copy-btn {
    background: rgba(0,255,157,0.1);
    border: 1px solid rgba(0,255,157,0.3);
    color: var(--accent);
    padding: 8px 16px;
    border-radius: 8px;
    cursor: pointer;
    font-family: var(--mono);
    font-size: 12px;
    font-weight: 600;
    transition: all 0.2s;
    white-space: nowrap;
  }
  .copy-btn:hover { background: rgba(0,255,157,0.2); }
  .copy-btn.copied { background: rgba(0,255,157,0.3); }

  .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 24px 0; }
  .stat-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 20px;
    text-align: center;
    transition: border-color 0.3s;
  }
  .stat-card:hover { border-color: var(--accent2); }
  .stat-num {
    font-family: var(--mono);
    font-size: 32px;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 4px;
  }
  .stat-label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
  .stat-total .stat-num { color: var(--text); }
  .stat-success .stat-num { color: var(--success); }
  .stat-error .stat-num { color: var(--danger); }

  .section { margin: 28px 0; }
  .section-title {
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--muted);
    font-family: var(--mono);
    margin-bottom: 14px;
    display: flex; align-items: center; gap: 8px;
  }
  .section-title::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }

  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 20px 24px;
  }

  .port-control {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .port-input {
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text);
    font-family: var(--mono);
    font-size: 16px;
    font-weight: 600;
    padding: 10px 16px;
    border-radius: 10px;
    width: 140px;
    transition: border-color 0.2s;
    outline: none;
  }
  .port-input:focus { border-color: var(--accent); }
  .update-btn {
    background: linear-gradient(135deg, var(--accent2), #9333ea);
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 10px;
    cursor: pointer;
    font-family: var(--sans);
    font-size: 14px;
    font-weight: 600;
    transition: opacity 0.2s;
  }
  .update-btn:hover { opacity: 0.85; }
  .update-btn.success {
    background: linear-gradient(135deg, #059669, #10b981);
  }

  .cert-section {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
  }
  .cert-info { font-size: 14px; color: var(--muted); line-height: 1.6; }
  .cert-info strong { color: var(--text); }
  .download-btn {
    background: linear-gradient(135deg, var(--accent3), #d97706);
    color: #1a0f00;
    border: none;
    padding: 10px 20px;
    border-radius: 10px;
    cursor: pointer;
    font-family: var(--sans);
    font-size: 14px;
    font-weight: 700;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    transition: opacity 0.2s;
    white-space: nowrap;
  }
  .download-btn:hover { opacity: 0.85; }

  .log-container {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px;
    font-family: var(--mono);
    font-size: 12px;
    max-height: 280px;
    overflow-y: auto;
  }
  .log-container::-webkit-scrollbar { width: 4px; }
  .log-container::-webkit-scrollbar-track { background: transparent; }
  .log-container::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
  .log-entry {
    padding: 6px 8px;
    border-radius: 6px;
    margin-bottom: 3px;
    display: flex;
    gap: 12px;
    align-items: center;
    transition: background 0.15s;
    animation: fadeIn 0.3s ease;
  }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: none; } }
  .log-entry:hover { background: rgba(255,255,255,0.03); }
  .log-time { color: var(--muted); min-width: 60px; }
  .log-method {
    min-width: 50px;
    font-weight: 700;
    text-align: center;
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 10px;
  }
  .method-GET { background: rgba(0,255,157,0.1); color: var(--accent); }
  .method-POST { background: rgba(124,58,237,0.2); color: #a78bfa; }
  .method-PUT { background: rgba(245,158,11,0.15); color: var(--accent3); }
  .method-DELETE { background: rgba(255,71,87,0.15); color: var(--danger); }
  .method-OTHER { background: rgba(255,255,255,0.05); color: var(--muted); }
  .log-status {
    min-width: 36px;
    text-align: center;
    font-weight: 600;
  }
  .status-2xx { color: var(--success); }
  .status-3xx { color: var(--accent3); }
  .status-4xx, .status-5xx { color: var(--danger); }
  .log-path { color: var(--text); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .log-ms { color: var(--muted); min-width: 60px; text-align: right; }
  .empty-log { color: var(--muted); text-align: center; padding: 32px; font-size: 13px; }

  .instructions {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 20px 24px;
  }
  .step {
    display: flex;
    gap: 16px;
    margin-bottom: 14px;
    align-items: flex-start;
  }
  .step:last-child { margin-bottom: 0; }
  .step-num {
    width: 26px; height: 26px;
    border-radius: 50%;
    background: linear-gradient(135deg, var(--accent2), var(--accent));
    display: flex; align-items: center; justify-content: center;
    font-size: 12px; font-weight: 700;
    flex-shrink: 0;
    margin-top: 1px;
  }
  .step-text { font-size: 14px; color: var(--muted); line-height: 1.6; }
  .step-text strong { color: var(--text); }
  .step-text code {
    font-family: var(--mono);
    background: rgba(255,255,255,0.07);
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 12px;
    color: var(--accent);
  }

  footer {
    text-align: center;
    padding: 32px;
    color: var(--muted);
    font-size: 12px;
    font-family: var(--mono);
  }

  @media (max-width: 600px) {
    .grid { grid-template-columns: 1fr 1fr; }
    .hero h1 { font-size: 28px; }
    .url-value { font-size: 15px; }
    .cert-section { flex-direction: column; }
  }
</style>
</head>
<body>

<header>
  <div class="logo">🔒</div>
  <div class="logo-text">Local<span>HTTPS</span>Proxy</div>
  <div class="status-pill">
    <span class="dot"></span>
    <span id="statusText">RUNNING</span>
  </div>
</header>

<main>
  <div class="hero">
    <h1>HTTPS for Local Dev</h1>
    <p>Camera • Geolocation • Secure APIs — no more browser blocks</p>
  </div>

  <div class="url-box">
    <div>
      <div class="url-label">HTTPS Proxy URL</div>
      <div class="url-value" id="proxyUrl">loading...</div>
    </div>
    <button class="copy-btn" id="copyBtn" onclick="copyUrl()">Copy</button>
  </div>

  <div class="grid">
    <div class="stat-card stat-total">
      <div class="stat-num" id="totalReq">0</div>
      <div class="stat-label">Total Requests</div>
    </div>
    <div class="stat-card stat-success">
      <div class="stat-num" id="successReq">0</div>
      <div class="stat-label">Successful</div>
    </div>
    <div class="stat-card stat-error">
      <div class="stat-num" id="errorReq">0</div>
      <div class="stat-label">Errors</div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Target Port</div>
    <div class="card">
      <div class="port-control">
        <div style="flex:1">
          <div style="font-size:13px;color:var(--muted);margin-bottom:8px;">Proxying to: <code style="font-family:var(--mono);color:var(--text)">http://127.0.0.1:<span id="currentPort">—</span></code></div>
          <div class="port-control">
            <input type="number" class="port-input" id="portInput" placeholder="8080" min="1" max="65535">
            <button class="update-btn" id="updateBtn" onclick="updatePort()">Update Port</button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">SSL Certificate</div>
    <div class="card cert-section">
      <div class="cert-info">
        <strong>Self-signed certificate</strong> — browsers will warn on first visit.<br>
        Click <strong>Advanced → Proceed</strong>, or install the cert below to trust it.
      </div>
      <a href="/cert" class="download-btn" download="local-https-proxy.crt">
        ⬇ Download Certificate
      </a>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Request Log</div>
    <div class="log-container" id="logContainer">
      <div class="empty-log">No requests yet — waiting for traffic...</div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">How to Use</div>
    <div class="instructions">
      <div class="step">
        <div class="step-num">1</div>
        <div class="step-text">Start your Spring Boot app on port <strong id="instrPort">8080</strong>, then open the proxy URL above on your phone/tablet.</div>
      </div>
      <div class="step">
        <div class="step-num">2</div>
        <div class="step-text">Browser will show a <strong>certificate warning</strong>. Click <code>Advanced</code> → <code>Proceed to site</code> to accept.</div>
      </div>
      <div class="step">
        <div class="step-num">3</div>
        <div class="step-text">For Android Chrome: Settings → Security → Install certificate. For iOS: Download cert → Settings → Trust.</div>
      </div>
      <div class="step">
        <div class="step-num">4</div>
        <div class="step-text">Now <strong>camera</strong>, <strong>geolocation</strong>, and other secure-context APIs will work normally over HTTPS!</div>
      </div>
    </div>
  </div>
</main>

<footer>
  Local HTTPS Proxy • Spring Boot Dev Tool • No data leaves your network
</footer>

<script>
let lastLogs = '';

async function fetchStats() {
  try {
    const r = await fetch('/api/stats');
    const d = await r.json();

    document.getElementById('totalReq').textContent = d.total;
    document.getElementById('successReq').textContent = d.success;
    document.getElementById('errorReq').textContent = d.errors;
    document.getElementById('proxyUrl').textContent = `https://${d.localIp}:${d.httpsPort}`;
    document.getElementById('currentPort').textContent = d.targetPort;
    document.getElementById('instrPort').textContent = d.targetPort;

    const newLogs = JSON.stringify(d.logs);
    if (newLogs !== lastLogs) {
      lastLogs = newLogs;
      renderLogs(d.logs);
    }
  } catch(e) {}
}

function renderLogs(logs) {
  const container = document.getElementById('logContainer');
  if (!logs || logs.length === 0) {
    container.innerHTML = '<div class="empty-log">No requests yet — waiting for traffic...</div>';
    return;
  }
  container.innerHTML = logs.map(entry => {
    const e = typeof entry === 'string' ? JSON.parse(entry) : entry;
    const methodClass = ['GET','POST','PUT','DELETE'].includes(e.method) ? e.method : 'OTHER';
    const statusClass = e.status >= 500 ? '5xx' : e.status >= 400 ? '4xx' : e.status >= 300 ? '3xx' : '2xx';
    return `<div class="log-entry">
      <span class="log-time">${e.time}</span>
      <span class="log-method method-${methodClass}">${e.method}</span>
      <span class="log-status status-${statusClass}">${e.status}</span>
      <span class="log-path">${e.path}</span>
      <span class="log-ms">${e.ms}ms</span>
    </div>`;
  }).join('');
}

function copyUrl() {
  const url = document.getElementById('proxyUrl').textContent;
  navigator.clipboard.writeText(url).then(() => {
    const btn = document.getElementById('copyBtn');
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
  });
}

async function updatePort() {
  const input = document.getElementById('portInput');
  const btn = document.getElementById('updateBtn');
  const port = parseInt(input.value);
  if (!port || port < 1 || port > 65535) { input.style.borderColor = 'var(--danger)'; return; }
  input.style.borderColor = '';

  try {
    const r = await fetch('/api/config', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({port})
    });
    if (r.ok) {
      btn.textContent = 'Updated!';
      btn.classList.add('success');
      input.value = '';
      setTimeout(() => { btn.textContent = 'Update Port'; btn.classList.remove('success'); }, 2000);
      fetchStats();
    }
  } catch(e) {}
}

document.getElementById('portInput').addEventListener('keypress', e => {
  if (e.key === 'Enter') updatePort();
});

fetchStats();
setInterval(fetchStats, 1500);
</script>
</body>
</html>
""";
        }
    }
}
