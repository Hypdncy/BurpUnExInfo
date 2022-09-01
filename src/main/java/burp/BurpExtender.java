package burp;

import java.awt.*;
import java.io.PrintWriter;
import java.net.URISyntaxException;
import java.util.*;
import java.util.List;
import java.net.URI;

public class BurpExtender implements IBurpExtender, IHttpListener, IMessageEditorTabFactory {
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static String PluginName = "Plugin: UnExInfo";
    public static String Author = "Author: Hypdncy";
    public static String Team = "Github: https://github.com/Hypdncy";

    public boolean isUnExInfo = false;

    public static Set<String> FileExts = Set.of(
            // 图片格式
            ".mp1", ".mp2", ".mp3", ".mp4", ".wma",
            ".wmv", ".rmvb", ".aac", ".wav", ".vqf", ".avi", ".mpg", ".mpeg",
            ".rm", ".mid", ".cda", "baz",
            // 视频格式
            "bmp", ".jpg", ".jpeg", ".png", ".tif", ".gif", ".svg",
            ".pcx", ".tga", ".exif", ".fpx", ".psd", ".cdr", ".pcd", ".dxf", ".ufo", ".eps",
            ".ai", ".raw", ".WMF", ".webp", ".avif", ".apng",
            // 文件格式
            ".pdf", ".xls", ".xlsx", ".doc", ".docx", ".ppt", ".pptx",
            // 字体格式
            ".woff2", ".woff", ".ttf",".otf"
    );


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 设置插件名字
        callbacks.setExtensionName("UnExInfo");
        BurpExtender.callbacks = callbacks;
        helpers = callbacks.getHelpers();

        // 注册
        callbacks.registerMessageEditorTabFactory(this);
        callbacks.registerHttpListener(this);

        // 输出插件信息
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        BurpExtender.stdout.println(PluginName);
        BurpExtender.stdout.println(Author);
        BurpExtender.stdout.println(Team);

    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageInfo == null) {
            return;
        }
        if (messageInfo.getRequest() == null) {
            return;
        }
        if (messageInfo.getResponse() == null) {
            return;
        }
        // 將請求包的頭部和内容分開
        byte[] request = messageInfo.getRequest();
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        List<String> requestInfoHeaders = requestInfo.getHeaders();
        // 获取请求头中URI，判断是否为不检索类型
        String header0 = requestInfoHeaders.get(0);
        String[] headerUri = header0.split(" ");
        if (headerUri.length == 3) {
            String stringUri = headerUri[1];
            try {
                URI uri = new URI(stringUri);
                String path = uri.getPath().toLowerCase();
                for (String ext : FileExts) {
                    if (path.endsWith(ext)) {
                        return;
                    }
                }
            } catch (URISyntaxException e) {
                stderr.println("Error Parse URI:" + header0);
                throw new RuntimeException(e);
            }
        }

        // 將返回包的頭部和内容分開
        byte[] response = messageInfo.getResponse();

        // 包的頭部和内容(未使用)
        //IResponseInfo ana_response = helpers.analyzeResponse(response);
        //byte[] byte_response = Arrays.copyOfRange(response, ana_response.getBodyOffset(), response.length);
        //byte[] byte_response_head = Arrays.copyOfRange(response, 0, ana_response.getBodyOffset());

        // 设置高亮
        //if (SensitiveInfo.IP(new String(response)).length() != 0 || SensitiveInfo.IP(new String(byte_request)).length() != 0){
        //    messageInfo.setHighlight("yellow");
        //}
        /* SensitiveInfo.Email(new String(request)).length() != 0 ||**/
        if (UnExInfo.Email(new String(response)).length() != 0) {
            messageInfo.setHighlight("yellow");
            isUnExInfo = true;
        }
        //if (SensitiveInfo.IP(new String(response)).length() != 0 /**|| SensitiveInfo.IP(new String(byte_request)).length() != 0**/ ){
        //    if (SensitiveInfo.in_ip(new String(response)) /**||SensitiveInfo.in_ip(new String(byte_request)) **/){
        //        messageInfo.setHighlight("red");
        //    }
        //}
        if (UnExInfo.in_ip(new String(response))) {
            messageInfo.setHighlight("red");
            isUnExInfo = true;

        }
        //if (SensitiveInfo.Password((new String(byte_response))).length() !=0){
        //    messageInfo.setHighlight("yellow");
        //}
        //if (SensitiveInfo.Address((new String(byte_response))).length() != 0){
        //    messageInfo.setHighlight("orange");
        //}
        /* SensitiveInfo.Phone(new String(request)).length() != 0 || **/
        if (UnExInfo.Phone(new String(response)).length() != 0) {
            messageInfo.setHighlight("green");
            isUnExInfo = true;

        }
        if (UnExInfo.IdCard(new String(request)).length() != 0 || UnExInfo.IdCard(new String(response)).length() != 0) {
            messageInfo.setHighlight("green");
            isUnExInfo = true;
        }
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new UnExInfoEditorTab(controller, isUnExInfo);

        //return new UnExInfoEditorTab();
    }

    static class UnExInfoEditorTab implements IMessageEditorTab {
        private boolean editable;
        private ITextEditor infoTextEditor;

        public UnExInfoEditorTab(IMessageEditorController controller, boolean editable) {
            this.editable = editable;

            //// create an instance of Burp's text editor, to display our deserialized data
            infoTextEditor = callbacks.createTextEditor();
            infoTextEditor.setEditable(false);
        }

        @Override
        public String getTabCaption() {
            return "UnExInfo";
        }

        @Override
        public Component getUiComponent() {
            return infoTextEditor.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            return editable;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {

            //取头部信息以及body信息 给js判断使用
            IResponseInfo response = helpers.analyzeResponse(content);
            List<String> headers = response.getHeaders();
            byte[] response_body = Arrays.copyOfRange(content, response.getBodyOffset(), content.length);

            // 引用规则匹配
            String infoText = "";
            String phone = UnExInfo.Phone(new String(content));
            String id = UnExInfo.IdCard(new String(content));
            String ip = UnExInfo.IP(new String(content));
            String email = UnExInfo.Email(new String(content));
//            String address = SensitiveInfo.Address(new String(content));
            String password = UnExInfo.Password(new String(content));

            // 设置文本
            if (phone.length() != 0) {
                infoText += "Exists phone information: " + phone + '\n' + '\n';
            }
            if (id.length() != 0) {
                infoText += "Exists IdCard information: " + id + '\n' + '\n';
            }
            if (ip.length() != 0) {
                infoText += "Exists ip information: " + ip + '\n' + '\n';
            }
            if (email.length() != 0) {
                infoText += "Exists email information: " + email + '\n' + '\n';
            }
            if (password.length() != 0) {
                infoText += "Exists Special Field (" + password + ")" + '\n' + '\n';
            }
            if (UnExInfo.js(headers.toString(), content)) {
                String path = UnExInfo.Path(new String(response_body));
                if (path.length() != 0) {
                    infoText += "Interface information: " + '\n' + path + '\n';
                }
            }
            if (UnExInfo.js(headers.toString(), content)) {
                String url = UnExInfo.Url(new String(response_body));
                if (url.length() != 0) {
                    infoText += "URL information: " + '\n' + url + '\n';
                }
            }
            //ITempFile tempFile = BurpExtender.callbacks.saveToTempFile(Text.getBytes(StandardCharsets.UTF_8));
            infoTextEditor.setText(helpers.stringToBytes(infoText));
        }

        @Override
        public byte[] getMessage() {
            return infoTextEditor.getText();
        }

        @Override
        public boolean isModified() {
            return false;
        }

        @Override
        public byte[] getSelectedData() {
            return infoTextEditor.getSelectedText();
        }
    }
}

