// Using CryptoJS
loadScript("./Crypto.js");

function getDate() {
  const date = new Date(timestamp * 1000);
  const year = date.getUTCFullYear();
  const month = ("0" + (date.getUTCMonth() + 1)).slice(-2);
  const day = ("0" + date.getUTCDate()).slice(-2);
  return `${year}-${month}-${day}`;
}

const timestamp = Math.floor(new Date().getTime() / 1000);
const date = getDate(timestamp);
const algorithm = "TC3-HMAC-SHA256";

let TencentCloudAPISign = function () {
  this.evaluate = function (context) {
    const requestId = context.getCurrentRequest().id;

    const requestHeaderHost = new DynamicValue(
      "com.luckymarmot.RequestURLDynamicValue",
      {
        request: requestId,
      }
    )
      .getEvaluatedString()
      .toString()
      .replace(/https:\/\//, "");
    const requestHeaderContentType = new DynamicValue(
      "com.luckymarmot.RequestHeaderDynamicValue",
      {
        request: requestId,
        header: "Content-Type",
      }
    ).getEvaluatedString();
    const requestRawBody = new DynamicValue(
      "com.luckymarmot.RequestRawBodyDynamicValue",
      {
        request: requestId,
      }
    ).getEvaluatedString();
    const requestMethod = new DynamicValue(
      "com.luckymarmot.RequestMethodDynamicValue",
      {
        request: requestId,
      }
    ).getEvaluatedString();

    const requestUriParms = "/";
    const requestQueryString = "";
    const requestCanonicalHeaders =
      "content-type:" +
      requestHeaderContentType.toLowerCase() +
      "\n" +
      "host:" +
      requestHeaderHost +
      "\n";

    const signedHeaders = "content-type;host";
    const hashedRequestBody = CryptoJS.SHA256(requestRawBody).toString(
      CryptoJS.enc.Hex
    );

    const canonicalRequest =
      "" +
      requestMethod +
      "\n" +
      requestUriParms +
      "\n" +
      requestQueryString +
      "\n" +
      requestCanonicalHeaders +
      "\n" +
      signedHeaders +
      "\n" +
      hashedRequestBody;

    const hashedCanonicalRequest = CryptoJS.SHA256(canonicalRequest).toString(
      CryptoJS.enc.Hex
    );

    const credentialScope =
      date + "/" + this.selectedService + "/" + "tc3_request";

    const stringToSign =
      algorithm +
      "\n" +
      timestamp +
      "\n" +
      credentialScope +
      "\n" +
      hashedCanonicalRequest;

    const secretDate = CryptoJS.HmacSHA256(date, "TC3" + this.secretKey);
    const secretService = CryptoJS.HmacSHA256(this.selectedService, secretDate);
    const secretSigning = CryptoJS.HmacSHA256("tc3_request", secretService);
    const signature = CryptoJS.HmacSHA256(stringToSign, secretSigning).toString(
      CryptoJS.enc.Hex
    );

    const authorization =
      algorithm +
      " " +
      "Credential=" +
      this.secretId +
      "/" +
      credentialScope +
      ", " +
      "SignedHeaders=" +
      signedHeaders +
      ", " +
      "Signature=" +
      signature;

    switch (this.output) {
      case "signature":
        return authorization;
      case "timestamp":
        return timestamp;
      case "host":
        return requestHeaderHost;
    }
  };
};

TencentCloudAPISign.inputs = [
  InputField("selectedService", "Cloud Service", "Select", {
    choices: {
      cvm: "CVM (Cloud Virtual Machine)",
    },
  }),
  InputField("secretId", "Secret ID", "String", {
    placeholder: "Enter your Secret ID here",
  }),
  InputField("secretKey", "Secret Key", "String", {
    placeholder: "Enter your Secret Key here",
  }),
  InputField("output", "Output Selection", "Radio", {
    choices: {
      signature: "Signature",
      timestamp: "Timestamps",
      host: "Host",
    },
    defaultValue: "signature",
  }),
];

TencentCloudAPISign.identifier = "me.Jimmy0w0.TencentCloudAPISign";
TencentCloudAPISign.title = "Tencent Cloud v3";

registerDynamicValueClass(TencentCloudAPISign);
