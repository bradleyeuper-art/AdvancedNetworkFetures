// ==========================================
// OSINT Networking Plugin v2
// WHOIS, Reverse DNS, ASN, GeoIP
// Public data only
// ==========================================

(function(){

if (typeof commands === "undefined") return;

// ----- Add Commands to Help Menu -----
commands["whois"] = "WHOIS lookup for domain ownership.";
commands["rdns"] = "Reverse DNS lookup for IP address.";
commands["asn"] = "ASN information for IP address.";
commands["geoip"] = "Public IP geolocation (city-level).";

// ----- Save Original Handler -----
const originalHandle = handle;

// ----- Utility: Private IP Detection -----
function isPrivateIP(ip){
    return (
        ip.startsWith("10.") ||
        ip.startsWith("192.168.") ||
        (ip.startsWith("172.") && (
            parseInt(ip.split(".")[1]) >= 16 &&
            parseInt(ip.split(".")[1]) <= 31
        ))
    );
}

// ----- Override Handle -----
handle = async function(input){

    const raw = input.trim();
    const parts = raw.split(" ");
    const cmd = parts[0].toLowerCase();
    const args = parts.slice(1).join(" ");

    // =========================
    // WHOIS
    // =========================
    if(cmd === "whois"){
        if(!args) return print("Provide a domain.");

        try{
            const r = await fetch(`https://api.whois.vu/?q=${encodeURIComponent(args)}`);
            const j = await r.json();

            if(!j || !j.domain) return print("No WHOIS data found.");

            print("Domain: " + j.domain);
            print("Registrar: " + (j.registrar || "Unknown"));
            print("Created: " + (j.created || "Unknown"));
            print("Expires: " + (j.expires || "Unknown"));
            print("Country: " + (j.country || "Unknown"));
        }catch{
            print("WHOIS lookup failed.");
        }

        return;
    }

    // =========================
    // Reverse DNS
    // =========================
    if(cmd === "rdns"){
        if(!args) return print("Provide an IP address.");

        try{
            const r = await fetch(`https://api.hackertarget.com/reversedns/?q=${encodeURIComponent(args)}`);
            const text = await r.text();

            if(text.includes("error")) return print("Reverse DNS failed.");
            print(text || "No PTR record found.");
        }catch{
            print("Reverse DNS failed.");
        }

        return;
    }

    // =========================
    // ASN Lookup
    // =========================
    if(cmd === "asn"){
        if(!args) return print("Provide an IP address.");

        try{
            const r = await fetch(`https://api.hackertarget.com/aslookup/?q=${encodeURIComponent(args)}`);
            const text = await r.text();

            if(text.includes("error")) return print("ASN lookup failed.");
            print(text || "ASN lookup failed.");
        }catch{
            print("ASN lookup failed.");
        }

        return;
    }

    // =========================
    // GeoIP
    // =========================
    if(cmd === "geoip"){

        let targetIP = args;

        try{

            // Auto detect public IP
            if(!targetIP){
                const ipRes = await fetch("https://api64.ipify.org?format=json");
                const ipJson = await ipRes.json();
                targetIP = ipJson.ip;
                print("Detected Public IP: " + targetIP);
            }

            if(isPrivateIP(targetIP)){
                return print("That is a private/internal IP. Cannot geolocate.");
            }

            const r = await fetch(`https://ipapi.co/${encodeURIComponent(targetIP)}/json/`);
            const j = await r.json();

            if(j.error) return print("GeoIP lookup failed.");

            print("IP: " + j.ip);
            print("City: " + (j.city || "Unknown"));
            print("Region: " + (j.region || "Unknown"));
            print("Country: " + (j.country_name || "Unknown"));
            print("ISP: " + (j.org || "Unknown"));

        }catch{
            print("GeoIP lookup failed.");
        }

        return;
    }

    // ----- Fallback -----
    return originalHandle(input);
};

print("[OSINT Networking Plugin Loaded]");

})();
