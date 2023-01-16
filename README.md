# 概述

wxwelinkorgcontroller存在sql注入漏洞，在登录泛微云桥之后，可以借助该漏洞执行sql注入语句。

> 注：泛微云桥中还有一些xxxorgcontroller存在类似的漏洞，它们并不是重复漏洞。从代码中可以看到，他们实现类似的功能，代码相似，各自代码独立，最终调用到的存在sql注入漏洞的函数也并不相同，即任何一个xxxorgcontroller被修补之后，其他所有的xxxorgcontroller依然可以单独完成sql注入。

# 影响版本

versions <= 最新(20221013)

# 审计过程

wxwelinkorgcontroller.exportOrg函数调用了wxWeLinkOrgInfoService.exportOrg函数，该函数关键代码如下：

```java
public File exportOrg(String syscorpid, String depts, String users, String fields, String syncond) throws Exception {
    ...
    sql.append(fields.replace(",efield_dept", "").replace("efield_dept,", "").replace("efield_dept", "").replace("efield_name", "u.name as efield_name").replace("efield_wxuserid", "u.wxuserid as efield_wxuserid").replace("efield_post", "u.post as efield_post").replace("efield_mobile", "u.mobile as efield_mobile").replace("efield_email", "u.email as efield_email").replace("efield_tel", "u.tel as efield_tel").replace("efield_jobnumber", "u.jobnumber as efield_jobnumber").replace("efield_status", "case when u.isattend = 1 then '已激活' else '未激活' end as efield_status").replace("efield_relatesys", "group_concat(c.sysname) as efield_relatesys").replace("efield_relateaccount", "group_concat(b.outsysuserid) as efield_relateaccount").replace("efield_lastsynerror", "u.lastsynerror as efield_lastsynerror"));
    ...
    if (!StrKit.notBlank(depts) && fields.indexOf("efield_dept") == -1) {
        ...
        if (StrKit.notBlank(users)) {
            models = WxCpUserInfoModel.dao.find(sql.toString(), ToolString.mergeAllSqlParams(new Object[]{syscorpid, ToolString.buildSqlInParams(users.replaceAll("\\|", ","))}));
        } else {
            models = WxCpUserInfoModel.dao.find(sql.toString(), new Object[]{syscorpid});
        }
    } else {
        ...
    }

    return ToolPOI.exportFile(fields.split(","), eFieldMap, "和飞信通讯录", "通讯录", models);
}
```

可以看到，这里的sql语句直接拼接了fields参数，并且最终会执行该sql语句。

wxwelinkorgcontroller.exportOrg调用wxWeLinkOrgInfoService.exportOrg函数的方式是这样的：

```java
public void exportOrg() {
    try {
        String syscorpid = this.getPara("syscorpid");
        String depts = this.getPara("depts");
        String users = this.getPara("users");
        String fields = this.getPara("fields");
        String syncond = this.getPara("syncond");
        if (StrKit.isBlank(syscorpid)) {
            this.renderJsonMsg("查询条件企业ID不能为空", false);
        } else if (StrKit.isBlank(fields)) {
            this.renderJsonMsg("请选择导出字段", false);
        } else {
            this.renderFile(this.wxWeLinkOrgInfoService.exportOrg(syscorpid, depts, users, fields, syncond));
        }
    } catch (Exception var6) {
        logger.error(var6.getMessage(), var6);
        this.renderJsonMsg("程序异常，请联系管理员！", false);
    }

}
```

可以看到，fields变量是由参数而来，因此我们可控，只需要控制条件分支最终走到sql语句执行的位置即可。

# 漏洞复现

见本仓库的Demonstrate.mp4文件。

# EXP

见本仓库的exp.py文件，使用方式是设置开头的参数（url、cookie、要执行的sql语句），执行即可，默认情况下使用报错注入执行，会将执行结果返回在命令行，也可以注释掉报错注入的代码，选择直接返回结果，直接返回结果的方式会将结果存储在当前目录下的test.xlxs中。

# 免责声明

本仓库仅用于学习使用，请勿用于实际场景，一切后果由使用者自负。