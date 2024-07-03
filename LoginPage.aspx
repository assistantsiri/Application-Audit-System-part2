<%@ Page Language="C#" AutoEventWireup="true" CodeFile="LoginPage.aspx.cs" Inherits="LoginPage" %>

<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title>Application Audit System</title>
    <script src="assets/jquery-3.7.1/jquery-3.7.1.min.js"></script>
    <link href="assets/bootstrap-5.3-dist/css/bootstrap.min.css" rel="stylesheet" />
    <script src="assets/bootstrap-5.3-dist/js/bootstrap.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>

    <style>
        body {
            /*background-image: linear-gradient(180deg, #019EEC, #FFB600);*/
            background-color: #019EEC;
            background-position: center center;
            background-repeat: no-repeat;
            background-size: cover;
            background-size: 100% 100%;
            overflow-x: hidden;
        }
    </style>
</head>
<body>
    <script src="lib/jquery/jquery.min.js"></script>

    <form id="form1" runat="server">
        <div>
            <div class="">
                <div class="row my-3">
                    <div class="col-3"></div>
                    <div class="col-6 border rounded p-5 bg-white" style="background-color: #dedede">
                        <h1 class="text-center"><b>Application Audit System</b> </h1>
                        <%--<h5 class="text-center">Application Audit System</h5>--%>
                        <div style="text-align: center">
                            <img src="Images/Syndicate-Bank-Canara-Bank.png" height="75" />
                        </div>
                        <div>
                            <div class="form-group mb-2">
                                <label class="form-label">User ID</label>
                                <asp:TextBox runat="server" ID="txtUserID" OnTextChanged="txtUserID_TextChanged" AutoPostBack="true" CssClass="form-control"></asp:TextBox>
                            </div>
                            <div class="form-group mb-2">
                                <label class="form-label">Select Post Audit/Pre-Audit</label>
                                <asp:DropDownList ID="ddlauditType" runat="server" CssClass="form-control" AutoPostBack="true" OnSelectedIndexChanged="ddlauditType_SelectedIndexChanged">
                                    <asp:ListItem Value="0">---Select---</asp:ListItem>
                                    <asp:ListItem Value="1">Pre-Application Audit</asp:ListItem>
                                    <asp:ListItem Value="2">Post-Application Audit</asp:ListItem>
                                </asp:DropDownList>
                            </div>
                            <div class="form-group mb-2">
                                <label class="form-label">Password</label>
                                <asp:TextBox ID="txtPwd" runat="server" CssClass="form-control" MaxLength="50" TextMode="Password"></asp:TextBox>
                            </div>
                            <div class="form-group mb-2">
                                <label class="form-label" for="ddlauditid">Audit ID</label>
                                <asp:DropDownList ID="ddlauditid" runat="server" CssClass="form-control"></asp:DropDownList>
                                <%--                                 <asp:RequiredFieldValidator ID="rqrdPwd0" runat="server" ControlToValidate="ddlauditid" ErrorMessage="Select Audit Id" ForeColor="#FF3300" ValidationGroup="FormValidation">*</asp:RequiredFieldValidator>--%>
                            </div>
                            <div class="text-center">
                                <%-- <asp:Button ID="btnUpdate" runat="server" CssClass="btn btn-primary" Text="Login" OnClientClick="Login(); return false;" ValidationGroup="FormValidation" />--%>
                                <%--                                
                               <asp:Button ID="btnLogin" runat="server" BackColor="#1589FF"  Text="Login" Width="80px" OnClientClick="Login(); return false;" TabIndex="3" />--%>
                                <asp:Button ID="btnLogin" runat="server" BackColor="#1589FF" Text="Login" Width="80px" OnClientClick="Login(); return false;" />
                                <%--<button type="button" class="btn btn-primary" onclick="Login()">Login</button>--%>
                                <asp:Button ID="btnCancel" runat="server" CssClass="btn btn-secondary" Text="Cancel" OnClientClick="btnCancel_Click" CausesValidation="False" />
                            </div>
                        </div>
                    </div>
                    <div class="col-3"></div>
                </div>
            </div>
        </div>
    </form>
    <%--<footer style="position: fixed; bottom: 0; text-align: center; left: 0" class="bg-white" id="footer">
        <p class="text-center">© 2024 Canbank Computer Services Ltd</p>
    </footer>--%>
</body>
</html>

<script type="text/javascript">

    function Login() {
        var userId = document.getElementById('<%= txtUserID.ClientID %>').value;
        var password = document.getElementById('<%= txtPwd.ClientID %>').value;
        <%-- var currentMaxAttempts = <%= Session["MaxAttempts"] %>;--%>
        var audittype = document.getElementById('<%= ddlauditType.ClientID %>');
        var selectedText = audittype.options[audittype.selectedIndex].innerHTML;
        var hashedPassword = CryptoJS.SHA512(password).toString();
        $.ajax({
            url: "LoginPage.aspx/LoginUser",
            type: "POST",
            dataType: "json",
            contentType: "application/json; charset=utf-8",
            data: "{'userId': '" + userId + "','hashedPassword': '" + hashedPassword + "','audittype': '" + selectedText + "'}",
            success: function (response) {
                var data = JSON.parse(response.d);
                if (data === "S") {
                    window.location.href = "./HomePage.aspx";
                }

                else if (data === "U") {
                    window.location.href = "./ChangePassword1.aspx";
                }

                else if (data === "P") {
                    window.location.href = "./PostAudit_New.aspx";
                }

                else if (data === "C") {
                    window.location.href = "./CompletedAuditReports_Post.aspx";
                }

                else {
                    alert(data);
                }
            },
            error: function (xhr, textStatus, errorThrown) {
                console.log("Error: " + errorThrown)  //Error handlers
                alert(errorThrown);
            }
        });
    }

</script>
