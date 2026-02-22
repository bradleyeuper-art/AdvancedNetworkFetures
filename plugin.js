// ==========================================
// OSINT Networking Plugin v3
// WHOIS, Reverse DNS, ASN, GeoIP, PublicIP
// Public data only
// ==========================================

(function(){

if (typeof commands === "undefined") return;

// ----- Add Commands to Help Menu -----
commands["whois"] = "WHOIS lookup for domain ownership.";
commands["rdns"] = "Reverse DNS lookup for IP address.";
commands["asn"] = "ASN information for IP address.";
commands["geoip"] = "Public IP geolocation (city-level).";
commands["publicip"] = "Show public IPv4 and IPv6 addresses.";

// ----- Save Original Handler -----
const originalHandle = handle;

// ----- Private IP Detection -----
function isPrivateIP(ip){
    if(!ip) return false;

    if(ip.startsWith("10.")) return true;
    if(ip.startsWith("192.168.")) return true;

    if(ip.startsWith("172.")){
        const second = parseInt(ip.split(".")[1]);
        if(second >= 16 && second <= 31) return true;
    }

    return false;
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

            // Auto-detect IP if not provided
            if(!targetIP){
                const ipRes = await fetch("https://api.ipify.org?format=json");
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

    // =========================
    // Public IP (IPv4 + IPv6)
    // =========================
    if(cmd === "publicip"){

        try{

            let ipv4 = null;
            let ipv6 = null;

            // IPv4
            try{
                const r4 = await fetch("https://api.ipify.org?format=json");
                const j4 = await r4.json();
                ipv4 = j4.ip;
            }catch{}

            // IPv6
            try{
                const r6 = await fetch("https://api64.ipify.org?format=json");
                const j6 = await r6.json();
                ipv6 = j6.ip;
            }catch{}

            if(!ipv4 && !ipv6){
                return print("Could not determine public IP.");
            }

            if(ipv4) print("Public IPv4: " + ipv4);
            if(ipv6 && ipv6 !== ipv4) print("Public IPv6: " + ipv6);

        }catch{
            print("Public IP lookup failed.");
        }

        return;
    }

    // ----- Fallback to original system -----
    return originalHandle(input);
};

print("[OSINT Networking Plugin v3 Loaded]");

})();
