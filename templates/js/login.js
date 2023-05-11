$("document").ready(function() {
    $("<div/>", {
        "appendTo": "#log",
        "class": "container"
    });
    $("<div/>", {
        "appendTo": ".container",
        "class": "rowCo"
    });
    $("<div/>", {
        "appendTo": ".rowCo",
        "class": "ctd",
        html: "<img><h1/><input/><input/><a><p/></a><a><div/></a><p/><p/>"
    });
    $(".ctd").find("img").attr({
        src: "https://i.328888.xyz/2023/05/11/iqU0AF.png",
        "class": "ctdimg"
    });
    $(".ctd").find("h1").eq(0).html("Welcome").attr({
        "class": "ctdh1",
    });
    $(".ctd").find("input").eq(0).attr({
        "class": "input-one",
        "placeHolder": "请输入用户名或邮箱",
        "name": "email",
        "type": "email",
        "autocomplete": "on",
        "required": "yes",
    });
    $(".ctd").find("input").eq(1).attr({
        "class": "input-one space15",
        "placeHolder": "请输入密码",
        "name": "password",
        "type": "password",
    });
    $(".ctd").find("a").eq(0).attr({
        href: "#",
    });
    $(".ctd").find("p").eq(0).html("忘记密码?").attr({
        "class": "ctdp1",
    });
    $(".ctd").find("a").eq(1).insertAfter(".ctdp1").attr({
        href: "#",
        "class": "alog",
    });
    $(".ctd").find("div").eq(0).html("登陆").attr({
        "class": "logdiv top15",
    });
    $(".ctd").find("p").eq(1).html("还没有账号?").attr({
        "class": "ctdp2",
    });
    /*click here and show ctd2*/
    $(".ctd").find("p").eq(2).html("立即注册").attr({
        "class": "ctdp3",
    });

    $("<div/>", {
        "appendTo": ".footer",
        "class": "ctdp4 top1",
        // html: "Copyright &#174 2018 DevLifeBlog. all rigths reserved.",
    });
   
   
    /*
    SECOND CONTAINER FOR SIGN UP
    */
    $("<div/>", {
        "appendTo": ".rowCo",
        "class": "ctd2",
        html: "<img><h1/><input/><input/><input/><input/><a><div/></a><p/>"
    });
    $(".ctd2").find("img").attr({
        src: "https://i.328888.xyz/2023/05/11/iqU0AF.png",
        "class": "ctdimg"
    });
    $(".ctd2").find("h1").eq(0).html("立即注册").attr({
        "class": "ctdh1",
    });
    $(".ctd2").find("input").eq(0).attr({
        "class": "input-one",
        "placeHolder": "用户名",
        "name": "name",
        "type": "text",
        "autocomplete": "off",
        "required": "yes",
    });
    $(".ctd2").find("input").eq(1).attr({
        "class": "input-one top5",
        "placeHolder": "邮箱",
        "name": "email",
        "type": "email",
        "autocomplete": "off",
        "required": "yes",
    });
    $(".ctd2").find("input").eq(2).attr({
        "class": "input-one top5",
        "placeHolder": "请输入密码",
        "name": "password",
        "type": "password",
        "required": "yes",
    });
    $(".ctd2").find("input").eq(3).attr({
        "class": "input-one top5",
        "placeHolder": "确认你的密码",
        "name": "password",
        "type": "password",
    });
    $(".ctd2").find("a").eq(0).attr({
        href: "#",
        "class": "alog",
    });
    $(".ctd2").find("div").eq(0).html("登陆").attr({
        "class": "logdiv top5",
    });
    $(".ctd2").find("p").eq(0).html("已有账户？立即登陆").attr({
        "class": "ctdp5",
    });
    /*
    EFFECTS AND EVENTS 
    */
    $("#").click(function(event){
        alert("thank you");
    });
    //using delay it seems more magic here, but this one it's was very easy
    $(".ctdp3").click(function(event){
        $(".ctd, .ctdp4").fadeOut("slow");
        $(".ctd2").delay(600).fadeIn("slow");
    });
    //now using reverse code, when the user are in the sign up form
    $(".ctdp5").click(function(event){
        $(".ctd2, .ctdp4").fadeOut("slow");
        $(".ctd, .ctdp4").delay(600).fadeIn("slow");
    });
});
