// =========================
// Public IP (Strict Check)
// =========================
if(cmd === "publicip"){

    try{

        let ipv4 = null;
        let ipv6 = null;

        const providers = [
            "https://api.ipify.org?format=json",
            "https://api64.ipify.org?format=json",
            "https://ifconfig.me/ip",
            "https://checkip.amazonaws.com"
        ];

        for(let url of providers){
            if(ipv4) break;
            try{
                const r = await fetch(url);
                const text = await r.text();

                let candidate;

                try{
                    const j = JSON.parse(text);
                    candidate = j.ip;
                }catch{
                    candidate = text.trim();
                }

                if(candidate) ipv4 = candidate;

            }catch{}
        }

        if(!ipv4) return print("Could not determine external IP.");

        // Private IP detection
        const isPrivate =
            ipv4.startsWith("10.") ||
            ipv4.startsWith("192.168.") ||
            (ipv4.startsWith("172.") && (
                parseInt(ipv4.split(".")[1]) >= 16 &&
                parseInt(ipv4.split(".")[1]) <= 31
            ));

        if(isPrivate){
            print("Network returned private IP: " + ipv4);
            print("You are behind NAT or network filtering.");
            return;
        }

        print("Public IPv4: " + ipv4);

        // Try IPv6 separately
        try{
            const r6 = await fetch("https://api64.ipify.org?format=json");
            const j6 = await r6.json();
            if(j6.ip && j6.ip !== ipv4){
                print("Public IPv6: " + j6.ip);
            }
        }catch{}

    }catch{
        print("Public IP lookup failed.");
    }

    return;
}
