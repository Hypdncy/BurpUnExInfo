package burp;

import java.awt.*;
import java.io.PrintWriter;
import java.net.URL;
import java.util.*;
import java.util.List;


public class BurpExtender implements IBurpExtender, IHttpListener, IMessageEditorTabFactory {
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static String PluginName = "Plugin: UnExInfo";
    public static String Author = "Author: Hypdncy";
    public static String Team = "Github: https://github.com/Hypdncy";

    public static boolean isUnExInfo = false;

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
            ".woff2", ".woff", ".ttf", ".otf"
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
        if (!messageIsRequest && messageInfo != null
                && messageInfo.getRequest() != null
                && messageInfo.getResponse() != null) {
            // 將請求包的頭部和内容分開
            URL url = helpers.analyzeRequest(messageInfo).getUrl();
            String path = url.getPath().toLowerCase();
            for (String ext : FileExts) {
                if (path.endsWith(ext)) {
                    return;
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
            }
            //if (SensitiveInfo.IP(new String(response)).length() != 0 /**|| SensitiveInfo.IP(new String(byte_request)).length() != 0**/ ){
            //    if (SensitiveInfo.in_ip(new String(response)) /**||SensitiveInfo.in_ip(new String(byte_request)) **/){
            //        messageInfo.setHighlight("red");
            //    }
            //}
            if (UnExInfo.in_ip(new String(response))) {
                messageInfo.setHighlight("red");
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
            }
            //UnExInfo.IdCard(new String(request)).length() != 0 ||
            if (UnExInfo.IdCard(new String(response)).length() != 0) {
                messageInfo.setHighlight("green");
            }
        }
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new UnExInfoEditorTab(controller, editable);
    }

    static class UnExInfoEditorTab implements IMessageEditorTab {
        private final ITextEditor infoTextEditor;
        private final Set<String> inMimeType = Set.of("text", "html", "json", "script", "xml");
        private boolean isShow = false;
        private String infoText = "";


        public UnExInfoEditorTab(IMessageEditorController controller, boolean editable) {

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
            // byte only req or res
            if (isRequest) {
                return false;
            } else {
                //取头部信息以及body信息 给js判断使用
                IResponseInfo response = helpers.analyzeResponse(content);
                String inferredMimeType = response.getInferredMimeType().toLowerCase();
                if (inferredMimeType.isEmpty() || !inMimeType.contains(inferredMimeType)) {
                    return false;
                }

                byte[] response_body = Arrays.copyOfRange(content, response.getBodyOffset(), content.length);

                // 引用规则匹配
                String text = "";
                String phone = UnExInfo.Phone(new String(content));
                String id = UnExInfo.IdCard(new String(content));
                String ip = UnExInfo.IP(new String(content));
                String email = UnExInfo.Email(new String(content));
                //String address = SensitiveInfo.Address(new String(content));
                String password = UnExInfo.Password(new String(content));

                // 设置文本
                if (phone.length() != 0) {
                    text += "Exists phone information: " + phone + '\n' + '\n';
                    isShow = true;

                }
                if (id.length() != 0) {
                    text += "Exists IdCard information: " + id + '\n' + '\n';
                    isShow = true;

                }
                if (ip.length() != 0) {
                    text += "Exists ip information: " + ip + '\n' + '\n';
                    isShow = true;

                }
                if (email.length() != 0) {
                    text += "Exists email information: " + email + '\n' + '\n';
                    isShow = true;

                }
                if (password.length() != 0) {
                    text += "Exists Special Field (" + password + ")" + '\n' + '\n';
                    isShow = true;

                }
                if (inferredMimeType.equals("script")) {
                    String path = UnExInfo.Path(new String(response_body));
                    if (path.length() != 0) {
                        text += "Interface information: " + '\n' + path + '\n';
                        isShow = true;
                    }
                    String stringUrl = UnExInfo.Url(new String(response_body));
                    if (stringUrl.length() != 0) {
                        text += "URL information: " + '\n' + stringUrl + '\n';
                        isShow = true;
                    }
                }

                infoText = text;
                return isShow;
            }
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (!isRequest) {
                infoTextEditor.setText(helpers.stringToBytes(infoText));
            }
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

