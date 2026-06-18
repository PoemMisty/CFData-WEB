package com.cfdata.web;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsetsController;
import android.view.WindowManager;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {
    private static final int PORT = 13335;
    private static final String BACKEND_LIBRARY = "libcfdata.so";
    private static final int REQUEST_CREATE_DOCUMENT = 1001;
    private static final int REQUEST_FILE_CHOOSER = 1002;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private WebView webView;
    private FrameLayout rootView;
    private View loadingView;
    private TextView loadingTitle;
    private TextView loadingMessage;
    private ProgressBar loadingSpinner;
    private Process backendProcess;
    private String pendingExportName;
    private byte[] pendingExportBytes;
    private ValueCallback<Uri[]> filePathCallback;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        rootView = new FrameLayout(this);
        webView = new WebView(this);
        rootView.addView(webView, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        loadingView = createLoadingView();
        rootView.addView(loadingView, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        setContentView(rootView, new ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        applySystemBarInsets(rootView);
        applyStatusBarTheme();
        configureWebView();
        startBackend();
    }

    private boolean isDarkMode() {
        int nightMode = getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
        return nightMode == Configuration.UI_MODE_NIGHT_YES;
    }

    private void applyStatusBarTheme() {
        setStatusBarAppearance(isDarkMode());
    }

    private void setStatusBarAppearance(boolean dark) {
        int bgColor = dark ? Color.rgb(15, 23, 42) : Color.rgb(246, 248, 251);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        getWindow().setStatusBarColor(bgColor);
        getWindow().setNavigationBarColor(bgColor);
        rootView.setBackgroundColor(bgColor);
        View decor = getWindow().getDecorView();
        int flags = decor.getSystemUiVisibility();
        if (dark) {
            decor.setSystemUiVisibility(flags & ~View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR);
        } else {
            decor.setSystemUiVisibility(flags | View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR);
        }
    }

    private View createLoadingView() {
        boolean dark = isDarkMode();
        FrameLayout overlay = new FrameLayout(this);
        overlay.setBackgroundColor(dark ? Color.rgb(15, 23, 42) : Color.rgb(246, 248, 251));

        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setGravity(Gravity.CENTER_HORIZONTAL);
        card.setPadding(dp(28), dp(30), dp(28), dp(28));
        card.setElevation(dp(8));

        GradientDrawable cardBackground = new GradientDrawable();
        cardBackground.setColor(dark ? Color.rgb(30, 41, 59) : Color.WHITE);
        cardBackground.setCornerRadius(dp(22));
        cardBackground.setStroke(dp(1), dark ? Color.argb(160, 51, 65, 85) : Color.argb(160, 226, 232, 240));
        card.setBackground(cardBackground);

        ImageView logo = new ImageView(this);
        logo.setImageResource(getApplicationInfo().icon);
        logo.setAdjustViewBounds(true);
        logo.setScaleType(ImageView.ScaleType.FIT_CENTER);
        LinearLayout.LayoutParams logoParams = new LinearLayout.LayoutParams(dp(64), dp(64));
        card.addView(logo, logoParams);

        loadingTitle = new TextView(this);
        loadingTitle.setText("CFData");
        loadingTitle.setTextColor(dark ? Color.rgb(241, 245, 249) : Color.rgb(31, 41, 55));
        loadingTitle.setTextSize(24);
        loadingTitle.setTypeface(Typeface.DEFAULT_BOLD);
        loadingTitle.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        titleParams.topMargin = dp(18);
        card.addView(loadingTitle, titleParams);

        loadingMessage = new TextView(this);
        loadingMessage.setText("正在启动本地服务...");
        loadingMessage.setTextColor(dark ? Color.rgb(148, 163, 184) : Color.rgb(100, 116, 139));
        loadingMessage.setTextSize(14);
        loadingMessage.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams messageParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        messageParams.topMargin = dp(8);
        card.addView(loadingMessage, messageParams);

        loadingSpinner = new ProgressBar(this);
        loadingSpinner.setIndeterminate(true);
        LinearLayout.LayoutParams spinnerParams = new LinearLayout.LayoutParams(dp(36), dp(36));
        spinnerParams.topMargin = dp(22);
        card.addView(loadingSpinner, spinnerParams);

        FrameLayout.LayoutParams cardParams = new FrameLayout.LayoutParams(Math.min(dp(320), getResources().getDisplayMetrics().widthPixels - dp(48)), ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.CENTER);
        overlay.addView(card, cardParams);
        return overlay;
    }

    private void applySystemBarInsets(View view) {
        view.setOnApplyWindowInsetsListener((v, insets) -> {
            v.setPadding(0, insets.getSystemWindowInsetTop(), 0, insets.getSystemWindowInsetBottom());
            return insets;
        });
        view.requestApplyInsets();
    }

    @SuppressLint({"SetJavaScriptEnabled", "AddJavascriptInterface"})
    private void configureWebView() {
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        webView.addJavascriptInterface(new AndroidBridge(), "CFDataAndroid");
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (uri != null && ("http".equals(uri.getScheme()) || "https".equals(uri.getScheme()))) {
                    String host = uri.getHost();
                    if ("127.0.0.1".equals(host) || "localhost".equals(host)) {
                        return false;
                    }
                    startActivity(new Intent(Intent.ACTION_VIEW, uri));
                    return true;
                }
                return false;
            }
        });
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback, FileChooserParams params) {
                if (filePathCallback != null) {
                    filePathCallback.onReceiveValue(null);
                }
                filePathCallback = callback;
                Intent intent = params.createIntent();
                intent.setType("*/*");
                intent.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{
                        "text/plain",
                        "text/csv",
                        "text/comma-separated-values",
                        "application/csv",
                        "application/vnd.ms-excel",
                        "application/octet-stream"
                });
                try {
                    startActivityForResult(intent, REQUEST_FILE_CHOOSER);
                } catch (ActivityNotFoundException e) {
                    filePathCallback = null;
                    Toast.makeText(MainActivity.this, "没有可用的文件选择器", Toast.LENGTH_LONG).show();
                    return false;
                }
                return true;
            }
        });
    }

    private void startBackend() {
        executor.execute(() -> {
            try {
                setLoadingMessage("正在准备本地服务...");
                File backend = prepareBackendBinary();
                ProcessBuilder builder = new ProcessBuilder(
                        backend.getAbsolutePath(),
                        "-host", "127.0.0.1",
                        "-port", String.valueOf(PORT)
                );
                builder.directory(getFilesDir());
                builder.redirectErrorStream(true);
                backendProcess = builder.start();
                setLoadingMessage("正在连接本地服务...");
                waitForBackend();
                mainHandler.post(() -> {
                    setLoadingMessage("正在加载界面...");
                    webView.loadUrl("http://127.0.0.1:" + PORT);
                });
            } catch (Exception e) {
                mainHandler.post(() -> showStartupError("启动失败", "本地服务启动失败，请重新打开应用\n" + e.getMessage()));
            }
        });
    }

    private void setLoadingMessage(String message) {
        mainHandler.post(() -> {
            if (loadingMessage != null) {
                loadingMessage.setText(message);
            }
        });
    }

    private void hideLoadingView() {
        View view = loadingView;
        if (view != null) {
            view.animate().alpha(0f).setDuration(180).withEndAction(() -> view.setVisibility(View.GONE)).start();
        }
    }

    private void showStartupError(String title, String message) {
        if (loadingView != null) {
            loadingView.setVisibility(View.VISIBLE);
            loadingView.setAlpha(1f);
        }
        if (loadingTitle != null) {
            loadingTitle.setText(title);
            loadingTitle.setTextColor(Color.rgb(185, 28, 28));
        }
        if (loadingMessage != null) {
            loadingMessage.setText(message);
        }
        if (loadingSpinner != null) {
            loadingSpinner.setVisibility(View.GONE);
        }
        Toast.makeText(this, title + ": " + message, Toast.LENGTH_LONG).show();
    }

    private File prepareBackendBinary() throws IOException {
        File nativeBackend = new File(getApplicationInfo().nativeLibraryDir, BACKEND_LIBRARY);
        if (nativeBackend.isFile()) {
            return nativeBackend;
        }
        throw new IOException("未找到内置后端: " + nativeBackend.getAbsolutePath());
    }

    private void waitForBackend() throws InterruptedException {
        long deadline = System.currentTimeMillis() + 15000;
        while (System.currentTimeMillis() < deadline) {
            if (isBackendReady()) {
                injectExportBridge();
                return;
            }
            Thread.sleep(300);
        }
        throw new IllegalStateException("本地服务启动超时");
    }

    private boolean isBackendReady() {
        HttpURLConnection connection = null;
        try {
            URL url = new URL("http://127.0.0.1:" + PORT + "/favicon.png");
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(500);
            connection.setReadTimeout(500);
            return connection.getResponseCode() < 500;
        } catch (IOException ignored) {
            return false;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private void injectExportBridge() {
        mainHandler.post(() -> webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                String script = "(function(){"
                        + "if(!window.CFDataAndroid||window.__cfdataAndroidExport)return;"
                        + "window.__cfdataAndroidExport=true;"
                        + "var old=window.downloadFile;"
                        + "window.downloadFile=function(content,nameBase,ext){"
                        + "var ts=new Date().toISOString().replace(/[-:T]/g,'').split('.')[0];"
                        + "var name=(nameBase||'cfdata-results')+'_'+ts+'.'+(ext||'txt');"
                        + "window.CFDataAndroid.saveTextFile(name,String(content||''));"
                        + "};"
                        + "})();";
                view.evaluateJavascript(script, null);
                hideLoadingView();
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (uri != null && ("http".equals(uri.getScheme()) || "https".equals(uri.getScheme()))) {
                    String host = uri.getHost();
                    if ("127.0.0.1".equals(host) || "localhost".equals(host)) {
                        return false;
                    }
                    startActivity(new Intent(Intent.ACTION_VIEW, uri));
                    return true;
                }
                return false;
            }
        }));
    }

    public class AndroidBridge {
        @JavascriptInterface
        public boolean isDarkMode() {
            int nightMode = getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
            return nightMode == Configuration.UI_MODE_NIGHT_YES;
        }

        @JavascriptInterface
        public void setDarkModeStatusBar(boolean dark) {
            mainHandler.post(() -> setStatusBarAppearance(dark));
        }

        @JavascriptInterface
        public void saveTextFile(String fileName, String content) {
            mainHandler.post(() -> {
                pendingExportName = sanitizeFileName(fileName);
                byte[] bom = new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
                byte[] data = content == null ? new byte[0] : content.getBytes(StandardCharsets.UTF_8);
                pendingExportBytes = new byte[bom.length + data.length];
                System.arraycopy(bom, 0, pendingExportBytes, 0, bom.length);
                System.arraycopy(data, 0, pendingExportBytes, bom.length, data.length);
                Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType(pendingExportName.endsWith(".csv") ? "text/csv" : "text/plain");
                intent.putExtra(Intent.EXTRA_TITLE, pendingExportName);
                startActivityForResult(intent, REQUEST_CREATE_DOCUMENT);
            });
        }
    }

    private String sanitizeFileName(String fileName) {
        String name = fileName == null ? "cfdata-results.txt" : fileName.replaceAll("[\\\\/:*?\"<>|]", "_").trim();
        return name.isEmpty() ? "cfdata-results.txt" : name;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_CREATE_DOCUMENT) {
            if (resultCode == RESULT_OK && data != null && data.getData() != null && pendingExportBytes != null) {
                try (OutputStream out = getContentResolver().openOutputStream(data.getData())) {
                    if (out != null) {
                        out.write(pendingExportBytes);
                        Toast.makeText(this, "已保存: " + pendingExportName, Toast.LENGTH_SHORT).show();
                    }
                } catch (IOException e) {
                    Toast.makeText(this, "保存失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
                }
            }
            pendingExportBytes = null;
            pendingExportName = null;
            return;
        }
        if (requestCode == REQUEST_FILE_CHOOSER) {
            if (filePathCallback == null) {
                return;
            }
            Uri[] result = WebChromeClient.FileChooserParams.parseResult(resultCode, data);
            filePathCallback.onReceiveValue(result);
            filePathCallback = null;
        }
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
            return;
        }
        super.onBackPressed();
    }

    @Override
    protected void onDestroy() {
        if (backendProcess != null) {
            backendProcess.destroy();
        }
        executor.shutdownNow();
        if (webView != null) {
            webView.destroy();
        }
        super.onDestroy();
    }
}
