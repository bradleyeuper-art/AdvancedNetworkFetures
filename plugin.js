// OSINT Networking Plugin
// Adds: whois, rdns, asn, geoip

(function(){

if (typeof commands === "undefined") return;

// ---- Add Help Menu Entries ----
commands["whois"] = "WHOIS lookup for domain ownership.";
commands["rdns"] = "Reverse DNS lookup for IP.";
commands["asn"] = "ASN info for IP address.";
commands["geoip"] = "Public IP geolocation (city-level).";

// ---- Save original handle ----
const originalHandle = handle;

// ---- Override handle ----
handle = async function(input){

    const raw = input.trim();
    const parts = raw.split(" ");
    const cmd = parts[0].toLowerCase();
    const args = parts.slice(1).join(" ");

    // WHOIS
    if(cmd === "whois"){
        if(!args) return print("Provide a domain.");
        try{
            const r = await fetch(`https://api.whois.vu/?q=${encodeURIComponent(args)}`);
            const j = await r.json();
            if(!j) return print("No data found.");

            print("Domain: " + j.domain);
            print("Registrar: " + j.registrar);
            print("Created: " + j.created);
            print("Expires: " + j.expires);
            print("Country: " + j.country);
        }catch{
            print("WHOIS lookup failed.");
        }
        return;
    }

    // Reverse DNS
    if(cmd === "rdns"){
        if(!args) return print("Provide an IP address.");
        try{
            const r = await fetch(`https://api.hackertarget.com/reversedns/?q=${encodeURIComponent(args)}`);
            const text = await r.text();
            print(text || "No PTR record found.");
        }catch{
            print("Reverse DNS failed.");
        }
        return;
    }

    // ASN
    if(cmd === "asn"){
        if(!args) return print("Provide an IP address.");
        try{
            const r = await fetch(`https://api.hackertarget.com/aslookup/?q=${encodeURIComponent(args)}`);
            const text = await r.text();
            print(text || "ASN lookup failed.");
        }catch{
            print("ASN lookup failed.");
        }
        return;
    }

    // GEOIP (City-Level)
    if(cmd === "geoip"){
        if(!args) return print("Provide an IP address.");
        try{
            const r = await fetch(`https://ipapi.co/${encodeURIComponent(args)}/json/`);
            const j = await r.json();
            if(j.error) return print("Lookup failed.");

            print("IP: " + j.ip);
            print("City: " + j.city);
            print("Region: " + j.region);
            print("Country: " + j.country_name);
            print("ISP: " + j.org);
        }catch{
            print("GeoIP lookup failed.");
        }
        return;
    }

    // fallback to original system
    return originalHandle(input);
};

print("[OSINT Plugin Loaded]");

})();
