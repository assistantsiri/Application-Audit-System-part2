using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using BO;
using BL;
using System.Data;
using System.Security.Cryptography;
using Newtonsoft.Json;
using System.Web.Services;
using System.Text;

public partial class LoginPage : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        if (!IsPostBack)
        {
            txtUserID.Focus();
            Session["MaxAttempts"] = 0;

        }
    }

    private string ComputeSha512Hash(string rawData, string salt)
    {
        byte[] saltBytes = Convert.FromBase64String(salt);
        byte[] rawDataBytes = Encoding.UTF8.GetBytes(rawData);

        byte[] combinedBytes = new byte[saltBytes.Length + rawDataBytes.Length];
        Array.Copy(saltBytes, 0, combinedBytes, 0, saltBytes.Length);
        Array.Copy(rawDataBytes, 0, combinedBytes, saltBytes.Length, rawDataBytes.Length);

        using (SHA512 sha512Hash = SHA512.Create())
        {
            // ComputeHash - returns byte array
            byte[] hashedBytes = sha512Hash.ComputeHash(combinedBytes);

            // Convert byte array to a string
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < hashedBytes.Length; i++)
            {
                builder.Append(hashedBytes[i].ToString("x2"));
            }
            return builder.ToString();
        }
    }


    [WebMethod]

    public static string LoginUser(string userId, string hashedPassword, string audittype)
    {


        LoginPage obj = new LoginPage();
        var loginstatus = obj.Logindtls(userId, hashedPassword, audittype);

        string jsonData = Newtonsoft.Json.JsonConvert.SerializeObject(loginstatus);
        //string sess = HttpContext.Current.Session["UserType"].ToString();
        // Return the JSON data
        return jsonData;


    }

    private string Logindtls(string userId, string hashedPassword, string audittype)
    {
        UserMaintenanceBAL objBL = new UserMaintenanceBAL();
        UserMaintenanceBO objBO = new UserMaintenanceBO();
        DataTable dTable1 = new DataTable();
        Session["StaffNum"] = userId;

        string sMsg = string.Empty;
        string flagstatus = string.Empty;
        try {

            objBO.StaffNo = Convert.ToInt32(userId).ToString();
            
            dTable1 = objBL.FetchUserMast(objBO);
            if (dTable1.Rows.Count > 0)
            {
                //all validation
                if (Convert.ToString(dTable1.Rows[0]["AUM_STATUS"]) == "I")
                {
                    Globals.Show("User is Inactive...Contact Admin!!!");
                    flagstatus = "User is Inactive...Contact Admin!!!";
                }

                if (dTable1.Rows[0]["AUM_USER_LOCK"].ToString() == "3")
                {
                    Globals.Show("User Locked...Contact Admin!!!");
                    flagstatus = "User Locked...Contact Admin!!!";
                }

                HttpContext.Current.Session["SALT"] = dTable1.Rows[0]["AUM_SALT"].ToString();
                HttpContext.Current.Session["Psw"] = hashedPassword;
                HttpContext.Current.Session["SALT_STAT"] = dTable1.Rows[0]["AUM_SALT_STATE"];

                string a;
                string storedHashedPassword;
                if (dTable1.Rows[0]["AUM_PWD"].ToString().Length != 128)
                    Session["Password"] = Globals.Decryptdata(dTable1.Rows[0]["AUM_PWD"].ToString());
                else
                    Session["Password"] = Globals.Decryptdata(dTable1.Rows[0]["AUM_PWD_HASHED"].ToString());
                //if (dTable1.Rows[0]["AUM_PWD"].ToString().Length != 128)
                //    a = Globals.Decryptdata(dTable1.Rows[0]["AUM_PWD"].ToString());
                //else
                //    a = Globals.Decryptdata(dTable1.Rows[0]["AUM_PWD_HASHED"].ToString());
                if (dTable1.Rows[0]["AUM_PWD"].ToString().Length == 128)
                    storedHashedPassword = Convert.ToString(dTable1.Rows[0]["AUM_PWD"]);
                else
                    storedHashedPassword = Convert.ToString(dTable1.Rows[0]["AUM_PWD_HASHED"]);
                string storedSalt = dTable1.Rows[0]["AUM_SALT"].ToString();
                string hashedPasswordWithSalt = ComputeSha512Hash(hashedPassword, storedSalt);


                HttpContext.Current.Session["StoredPsw"] = Convert.ToString(hashedPasswordWithSalt);

                Session["UserID"] = userId;

                Session["RoleID"] = dTable1.Rows[0]["AUM_ROLE"].ToString();

                //Session["Pwd"] = txtPwd.Text;

                objBO.ValidTo = dTable1.Rows[0]["AUM_VALIDTO"].ToString();
                var sysdt = DateTime.Now;
                var exprdt = Convert.ToDateTime(objBO.ValidTo);
                //exprdt = exprdt.Substring(6, 4) + exprdt.Substring(3, 2) + exprdt.Substring(0, 2);
                
                if (exprdt > sysdt)
                {
                    //Response.Redirect("Home.aspx");
                    flagstatus = "S";
                    if (hashedPasswordWithSalt != storedHashedPassword)
                    {
                        //ViewState["MaxAttempts"] = Convert.ToInt32(ViewState["MaxAttempts"]) + 1;
                        ViewState["MaxAttempts"] = 1;

                        if (Convert.ToInt32(ViewState["MaxAttempts"]) < 3)
                        {
                            Globals.Show("Invalid Password...Try again!!!");
                            flagstatus = "Invalid Password...Try again!!!";
                        }
                        else if (ViewState["MaxAttempts"].ToString() == "3")
                        {
                            DataTable dTAudit = new DataTable();
                            dTAudit = objBL.FetchAuditId(objBO);
                            Session["VauditId"] = Convert.ToInt32(dTAudit.Rows[0]["AAT_AASAUDITID"]);
                            
                            objBO.auditid = Convert.ToInt32(Session["VauditId"]);
                            objBO.StaffNo = Convert.ToString(txtUserID.Text);
                            objBO.Action = "L";
                            objBO.UpdtBy = txtUserID.Text;
                            Byte smsg = objBL.SaveUpdateLoginattempt(objBO);
                            if (smsg == 1)
                                Globals.Show("User locked!!!");
                            flagstatus = "User locked!!!";
                        }
                    }
                    else if (hashedPasswordWithSalt == storedHashedPassword)
                    {
                        objBO.auditid = Convert.ToInt32(Session["VauditId"]);
                        objBO.StaffNo = userId;
                        DataTable dTableLog = objBL.FetchUserMastLog(objBO);
                        string Logattempt = Convert.ToString(dTableLog.Rows[0]["AUL_LOG_ATTEMPT"]);
                        DataTable dTable = objBL.FetchUserMast(objBO);

                        if (audittype == "Pre-Application Audit")
                        {
                            DataTable dTAudit = new DataTable();
                            dTAudit = objBL.FetchAuditId(objBO);
                            if (dTAudit.Rows.Count > 0)
                            {
                                if (Convert.ToInt32(dTAudit.Rows[0]["AAT_AASAUDITID"]) == 0)
                                {
                                    Session["VauditId"] = 0;

                                }
                                else
                                {
                                    Session["VauditId"] = Convert.ToInt32(dTAudit.Rows[0]["AAT_AASAUDITID"]);
                                }

                            }

                            objBO.Action = "U";
                            Byte i = objBL.SaveUpdateLoginattempt(objBO);
                            flagstatus = "S";
                            //Response.Redirect("HomePage.aspx");
                        }

                        else if (audittype == "Post-Application Audit")
                        {
                            DataTable dTAudit = new DataTable();
                            dTAudit = objBL.FetchAuditIdPost(objBO);
                            if (dTAudit.Rows.Count > 0)
                            {
                                if (Convert.ToInt32(dTAudit.Rows[0]["AAT_AASAUDITID"]) == 0)
                                {
                                    Session["VauditId"] = 0;

                                }
                                else
                                {
                                    Session["VauditId"] = Convert.ToInt32(dTAudit.Rows[0]["AAT_AASAUDITID"]);
                                }

                            }

                            objBO.Action = "U";
                            Byte i = objBL.SaveUpdateLoginattempt(objBO);
                            //Response.Redirect("PostAudit.aspx");
                            //Response.Redirect("PostAudit_New.aspx");
                            flagstatus = "P";

                        }
                        //Added shwetha On 14-11-2016
                        if (Convert.ToInt32(Session["DeptId"].ToString()) == 1)
                        {
                            if ((Convert.ToInt32(Session["RoleId"].ToString()) != 1 && Convert.ToInt32(Session["RoleId"].ToString()) != 9) && Convert.ToInt32(Session["RoleId"].ToString()) == 2)
                            {
                                //Modified on 11-08-2017 as per feedbacks given (to generate reports after conclude Audit)
                                if (ddlauditid.SelectedValue == "0")
                                {
                                    //Response.Redirect("CompletedAuditReports_Post.aspx");
                                    flagstatus = "C";
                                }
                                //11-08-2017
                                //if (ddlauditid.SelectedItem.Text == "Completed Audit Reports")

                                if (Convert.ToInt32(Session["VauditId"].ToString()) != 0)
                                {
                                    ViewState["AuditId"] = Convert.ToInt32(Session["VauditId"].ToString());
                                }
                                else
                                {
                                    String sMessage = "User not inducted for audit..";
                                    ScriptManager.RegisterClientScriptBlock(this, this.GetType(), "alertMessage", "alert('User Not Inducted for Audit.')", true);
                                    flagstatus = "User not inducted for audit..";
                                }
                            }
                        }


                        if ((Convert.ToInt32(Session["RoleId"].ToString()) == 2 && Convert.ToInt32(Session["DeptId"].ToString()) == 1))
                        {
                            Session["VauditId"] = Convert.ToInt32(ddlauditid.SelectedValue);
                        }
                    }
                }
                else
                {
                    //Response.Redirect("ChangePassword.aspx");
                    flagstatus = "U";
                    flagstatus = flagstatus;
                }

            }
            else
            {
                Globals.Show("Invalid User Id...Try again!!!");
                txtUserID.Focus();
                flagstatus = "Invalid User Id...Try again!!!";
                //return flagstatus;
            }
        }
        catch (Exception ee)
        {

            Globals.Show(ee.Message.ToString());
            flagstatus = ee.Message + "-" + ee.Source + "-" + ee.StackTrace;

        }
        finally
        {
            objBL = null;
            objBO = null;
            sMsg = null;
        }
        return flagstatus;
       
      

        //objBO.M_AUDIT_type1 = ddlauditType.SelectedItem.Text;
        //DataTable dTAudit = new DataTable();
        //dTAudit = objBL.FetchAuditId(objBO);
        //if (dTAudit.Rows.Count > 0)
        //{
        //    if (Convert.ToInt16(dTAudit.Rows[0]["AAT_AASAUDITID"]) == 0)
        //    {
        //        Session["VauditId"] = 0;

        //    }
        //    else
        //    {
        //        Session["VauditId"] = Convert.ToInt16(dTAudit.Rows[0]["AAT_AASAUDITID"]);
        //    }

        //}

    }








    protected void btnLogin_Click(object sender, EventArgs e)
    {
        Session["StaffNum"] = txtUserID.Text;
        UserMaintenanceBAL objBL = new UserMaintenanceBAL();
        UserMaintenanceBO objBO = new UserMaintenanceBO();
        DataTable dTable1 = new DataTable();
        string sMsg;
        objBO.StaffNo = txtUserID.Text;
        objBO.UpdtDt = DateTime.Now.ToString("dd-MMM-yyyy");
                        dTable1 = objBL.FetchUserMast(objBO);
                        if (dTable1.Rows.Count > 0)
                        {
                            if (Convert.ToString(dTable1.Rows[0]["AUM_STATUS"]) == "I")
                            {
                                Globals.Show("User is Inactive...Contact Admin!!!");
                                return;
                            }

                            if (dTable1.Rows[0]["AUM_USER_LOCK"].ToString() == "3")
                            {
                                Globals.Show("User Locked...Contact Admin!!!");
                                return;
                            }
                            objBO.Pwd = Globals.Decryptdata(Convert.ToString(dTable1.Rows[0]["AUM_PWD_HASHED"]));
                            if (objBO.Pwd != txtPwd.Text)
                            {

                                ViewState["MaxAttempts"] = Convert.ToByte(ViewState["MaxAttempts"]) + 1;
                                if (Convert.ToInt16(ViewState["MaxAttempts"]) < 3)
                                {
                                    Globals.Show("Invalid Password...Try again!!!");
                                }
                                else if (ViewState["MaxAttempts"].ToString() == "3")
                                {
                                    DataTable dTAudit = new DataTable();
                                    dTAudit = objBL.FetchAuditId(objBO);
                                    Session["VauditId"] = Convert.ToInt16(dTAudit.Rows[0]["AAT_AASAUDITID"]);
                                    objBO.auditid = Convert.ToInt32(Session["VauditId"]);
                                    objBO.StaffNo = Convert.ToString(txtUserID.Text);
                                    objBO.Action = "L";
                                    objBO.UpdtBy = txtUserID.Text;
                                    Byte smsg = objBL.SaveUpdateLoginattempt(objBO);
                                    if (smsg == 1)
                                        Globals.Show("User locked!!!");
                                    return;
                                }

                            }
                            else
                            {
                                objBO.auditid = Convert.ToInt32(Session["VauditId"]);
                                objBO.StaffNo = txtUserID.Text;
                                DataTable dTableLog = objBL.FetchUserMastLog(objBO);
                                string Logattempt = Convert.ToString(dTableLog.Rows[0]["AUL_LOG_ATTEMPT"]);
                                if (Convert.ToString(Logattempt) == "")
                                {
                                    Logattempt = "0";
                                }
                                if (Logattempt == "0")
                                {
                                    Response.Redirect("ChangePassword1.aspx");
                                }
                                DataTable dTable = objBL.FetchUserMast(objBO);
                                //if (dTable.Rows.Count > 0)
                                //{
                                //    String Password = Convert.ToString(dTable.Rows[0]["AUM_PWD"]);

                                //    string pwd = Globals.Decryptdata(Password);

                                //    if (Globals.Decryptdata(Password) != txtPwd.Text)
                                //    {

                                //        String sMessage = "Invalid Password..";
                                //        ScriptManager.RegisterStartupScript(this, typeof(Page), "Alert", "<script>alert('" + sMessage + "');</script>", false);
                                //        return;

                                //    }
                                //}
                                if (ddlauditType.SelectedItem.Text == "Pre-Application Audit")
                                {
                                    DataTable dTAudit = new DataTable();
                                    dTAudit = objBL.FetchAuditId(objBO);
                                    if (dTAudit.Rows.Count > 0)
                                    {
                                        if (Convert.ToInt16(dTAudit.Rows[0]["AAT_AASAUDITID"]) == 0)
                                        {
                                            Session["VauditId"] = 0;

                                        }
                                        else
                                        {
                                            Session["VauditId"] = Convert.ToInt16(dTAudit.Rows[0]["AAT_AASAUDITID"]);
                                        }

                                    }

                                    objBO.Action = "U";
                                    Byte i = objBL.SaveUpdateLoginattempt(objBO);
                                    Response.Redirect("HomePage.aspx");
                                }

                                else if (ddlauditType.SelectedItem.Text == "Post-Application Audit")
                                {
                                    DataTable dTAudit = new DataTable();
                                    dTAudit = objBL.FetchAuditIdPost(objBO);
                                    if (dTAudit.Rows.Count > 0)
                                    {
                                        if (Convert.ToInt16(dTAudit.Rows[0]["AAT_AASAUDITID"]) == 0)
                                        {
                                            Session["VauditId"] = 0;

                                        }
                                        else
                                        {
                                            Session["VauditId"] = Convert.ToInt16(dTAudit.Rows[0]["AAT_AASAUDITID"]);
                                        }

                                    }

                                    objBO.Action = "U";
                                    Byte i = objBL.SaveUpdateLoginattempt(objBO);
                                    //Response.Redirect("PostAudit.aspx");
                                    Response.Redirect("PostAudit_New.aspx");


                                }
                                //Added shwetha On 14-11-2016
                                if (Convert.ToInt16(Session["DeptId"].ToString()) == 1)
                                {
                                    if ((Convert.ToInt16(Session["RoleId"].ToString()) != 1 && Convert.ToInt16(Session["RoleId"].ToString()) != 9) && Convert.ToInt16(Session["RoleId"].ToString()) == 2)
                                    {
                                        //Modified on 11-08-2017 as per feedbacks given (to generate reports after conclude Audit)
                                        if (ddlauditid.SelectedValue == "0")
                                        {
                                            Response.Redirect("CompletedAuditReports_Post.aspx");
                                        }
                                        //11-08-2017
                                        //if (ddlauditid.SelectedItem.Text == "Completed Audit Reports")

                                        if (Convert.ToInt32(Session["VauditId"].ToString()) != 0)
                                        {
                                            ViewState["AuditId"] = Convert.ToInt32(Session["VauditId"].ToString());
                                        }
                                        else
                                        {
                                            ScriptManager.RegisterClientScriptBlock(this, this.GetType(), "alertMessage", "alert('User Not Inducted for Audit.')", true);
                                            return;
                                        }
                                    }
                                }


                                if ((Convert.ToInt16(Session["RoleId"].ToString()) == 2 && Convert.ToInt16(Session["DeptId"].ToString()) == 1))
                                {
                                    Session["VauditId"] = Convert.ToInt32(ddlauditid.SelectedValue);
                                }
                            }
                        }
        //objBO.M_AUDIT_type1 = ddlauditType.SelectedItem.Text;
        //DataTable dTAudit = new DataTable();
        //dTAudit = objBL.FetchAuditId(objBO);
        //if (dTAudit.Rows.Count > 0)
        //{
        //    if (Convert.ToInt16(dTAudit.Rows[0]["AAT_AASAUDITID"]) == 0)
        //    {
        //        Session["VauditId"] = 0;

        //    }
        //    else
        //    {
        //        Session["VauditId"] = Convert.ToInt16(dTAudit.Rows[0]["AAT_AASAUDITID"]);
        //    }

        //}

        
        //   Change password and invalid password validation
        
            





       

        //DataTable dTable = objBL.FetchUserMast(objBO);
        //if (dTable.Rows.Count > 0)
        //{
        //    String Password = Convert.ToString(dTable.Rows[0]["AUM_PWD"]);



        //    if (Globals.Decryptdata(Password) != txtPwd.Text)
        //    {

        //        String sMessage = "Invalid Password..";
        //        ScriptManager.RegisterStartupScript(this, typeof(Page), "Alert", "<script>alert('" + sMessage + "');</script>", false);

        //    }
        //if (ddlauditType.SelectedItem.Text == "Pre-Application Audit")
        //{
        //    DataTable dTAudit = new DataTable();
        //    dTAudit = objBL.FetchAuditId(objBO);
        //    if (dTAudit.Rows.Count > 0)
        //    {
        //        if (Convert.ToInt16(dTAudit.Rows[0]["AAT_AASAUDITID"]) == 0)
        //        {
        //            Session["VauditId"] = 0;

        //        }
        //        else
        //        {
        //            Session["VauditId"] = Convert.ToInt16(dTAudit.Rows[0]["AAT_AASAUDITID"]);
        //        }

        //    }

        //    objBO.Action = "U";
        //    Byte i = objBL.SaveUpdateLoginattempt(objBO);
        //    Response.Redirect("HomePage.aspx");
        //}

        //else if (ddlauditType.SelectedItem.Text == "Post-Application Audit")
        //{
        //    DataTable dTAudit = new DataTable();
        //    dTAudit = objBL.FetchAuditIdPost(objBO);
        //    if (dTAudit.Rows.Count > 0)
        //    {
        //        if (Convert.ToInt16(dTAudit.Rows[0]["AAT_AASAUDITID"]) == 0)
        //        {
        //            Session["VauditId"] = 0;

        //        }
        //        else
        //        {
        //            Session["VauditId"] = Convert.ToInt16(dTAudit.Rows[0]["AAT_AASAUDITID"]);
        //        }

        //    }

        //    objBO.Action = "U";
        //    Byte i = objBL.SaveUpdateLoginattempt(objBO);
        //    //Response.Redirect("PostAudit.aspx");
        //    Response.Redirect("PostAudit_New.aspx");
           

        //}


    }

    //if (dTableLog.Rows.Count > 0)
    //      {
    //          DataTable dTLog = new DataTable();

    //          dTLog = objBL.FetchLoginattempts(objBO);
    //          if (dTLog.Rows.Count > 0)
    //          {
    //              objBO.Action = "U";
    //          }
    //          else
    //          {
    //              objBO.Action = "I";
    //          }

    public string StrMonth(string strMon)
    {

        string output = string.Empty;

        if (strMon == "01")
        {
            strMon = "JAN";
        }
        else if (strMon == "02")
        {
            strMon = "FEB";
        }
        else if (strMon == "03")
        {
            strMon = "MAR";
        }
        else if (strMon == "04")
        {
            strMon = "APR";
        }
        else if (strMon == "05")
        {
            strMon = "MAY";
        }
        else if (strMon == "06")
        {
            strMon = "JUN";
        }
        else if (strMon == "07")
        {
            strMon = "JUL";
        }
        else if (strMon == "08")
        {
            strMon = "AUG";
        }
        else if (strMon == "09")
        {
            strMon = "SEP";
        }
        else if (strMon == "10")
        {
            strMon = "OCT";
        }
        else if (strMon == "11")
        {
            strMon = "NOV";
        }
        else if (strMon == "12")
        {
            strMon = "DEC";
        }

        return strMon;

    }
    private void FillAuditId()
    {
        UserMaintenanceBAL objBL = new UserMaintenanceBAL();
        UserMaintenanceBO objBO = new UserMaintenanceBO();

        try
        {
            if (ddlauditType.SelectedValue == "1")
            {
                objBO.Action = "A";
            }
            else if (ddlauditType.SelectedValue == "2")
            {
                objBO.Action = "B";
            }
            else if (ddlauditType.SelectedValue == "0")
            {
                //String sMessage = "Select Post Audit/Pre-Audit";
                //ScriptManager.RegisterStartupScript(this, typeof(Page), "Alert", "<script>alert('" + sMessage + "');</script>", false);
                // return;
            }
            objBO.StaffNo = txtUserID.Text;
            DataTable dtable = objBL.AudtidIdLoad(objBO);
            ddlauditid.DataSource = dtable;
            ddlauditid.DataValueField = "aat_aasauditid";
            ddlauditid.DataTextField = "appname";
            ddlauditid.DataBind();
            ddlauditid.Items.Insert(0, new ListItem("--Select--", ""));
            //Modified on 11-08-2017 as per feedbacks given (to generate reports after conclude Audit)
            ddlauditid.Items.Insert(1, new ListItem("Completed Audit Reports", "0"));
        }
        catch (Exception ex)
        {
            ScriptManager.RegisterClientScriptBlock(this, this.GetType(), "alertMessage", "alert(" + ex.Message.ToString() + ")", true);
        }
        finally
        {
            objBL = null;
            ddlauditid = null;
        }
    }

    protected void txtUserID_TextChanged(object sender, EventArgs e)
    {

        UserMaintenanceBAL objBL = new UserMaintenanceBAL();
        UserMaintenanceBO objBO = new UserMaintenanceBO();
        string s = txtUserID.Text.Trim();
        string UserID = s.Replace("'", " ");
        objBO.StaffNo = UserID;
        try
        {



            //  Int16 UserLength = Convert.ToInt16(txtUserID.Text.Length);
            //if ((UserLength >=5) && (UserLength >=6))
            //{
            //    string message = "User ID Should be of length 5 or 6 ";
            //    ClientScript.RegisterStartupScript(this.GetType(), "myalert", "alert('" + message + "');", true);
            //    txtUserID.Text = "";
            //    return;
            //}
            objBO.Action = "D";
            DataTable dTable = objBL.FetchUserDtls(objBO);

            if (dTable.Rows.Count == 0)
            {
                string message = "Invalid Staff ID ";
                ClientScript.RegisterStartupScript(this.GetType(), "myalert", "alert('" + message + "');", true);
                txtUserID.Text = "";
            }

            else
            {
                Session["DeptId"] = Convert.ToInt16(dTable.Rows[0]["AUM_DEPT"]);
                Session["RoleId"] = Convert.ToInt16(dTable.Rows[0]["AUM_ROLE"]);
                Session["Designation"] = Convert.ToInt16(dTable.Rows[0]["AUM_DESIGNATION"]);
                Session["Section"] = Convert.ToString(dTable.Rows[0]["AUM_SECTION"]);
                Session["SectionName"] = Convert.ToString(dTable.Rows[0]["secname"]);
                Session["WingName"] = Convert.ToString(dTable.Rows[0]["wing"]);
                String UpdtStatus = Convert.ToString(dTable.Rows[0]["AUM_UPDT_STAT"]).ToString();
                String Status = Convert.ToString(dTable.Rows[0]["AUM_STATUS"]).ToString();
                String RoleId = Convert.ToString(Session["RoleId"]);


                if ((Convert.ToInt16(Session["RoleId"].ToString()) == 2 && Convert.ToInt16(Session["DeptId"].ToString()) == 1))
                {
                    // lblauditid.Visible = true;
                    ddlauditid.Visible = true;
                    FillAuditId();
                }
                else
                {
                    // lblauditid.Visible = false;
                    ddlauditid.Visible = false;
                }



                if (UpdtStatus != "A" && RoleId != "1" && Status != "I")
                {
                    ScriptManager.RegisterClientScriptBlock(this, this.GetType(), "alertMessage", "alert('User ID has to be Authorised...')", true);
                    txtUserID.Text = "";
                    txtUserID.Focus();
                }
                else
                {
                    txtPwd.Focus();
                }

            }
        }
        catch (Exception ee)
        {
            Globals.Show(ee.Message.ToString());
        }
    }


    //protected void txtPwd_TextChanged(object sender, EventArgs e)
    //{


    //}

    protected void ImgBtnHome_Click(object sender, ImageClickEventArgs e)
    {

    }

    protected void ImgBtnLogout_Click(object sender, ImageClickEventArgs e)
    {

    }

    protected void btnCancel_Click(object sender, EventArgs e)
    {
        txtUserID.Text = "";
        txtPwd.Text = "";
        // lblauditid.Visible = false;
        //ddlauditid.Visible = false;
    }

    //protected void ddlauditType_SelectedIndexChanged(object sender, EventArgs e)
    //{

    //}



    protected void ddlauditType_SelectedIndexChanged(object sender, EventArgs e)
    {
        FillAuditId();
    }
}