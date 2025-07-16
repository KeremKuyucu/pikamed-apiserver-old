const express = require("express");
const axios = require("axios");
const fs = require('fs');
const path = require("path");
const router = express.Router();
const dayjs = require("dayjs");
const https = require("https");
const FormData = require("form-data");
const cron = require('node-cron');
require("dotenv").config();
require("dayjs/locale/tr");
const isoWeek = require("dayjs/plugin/isoWeek");
const firebaseAdmin = require("firebase-admin");
const Mailjet = require("node-mailjet");
const mailjet = Mailjet.apiConnect( process.env.MAILJET_API_KEY, process.env.MAILJET_SECRET_KEY );
firebaseAdmin.initializeApp({
  credential: firebaseAdmin.credential.cert({
    type: process.env.pikamed_FIREBASE_TYPE,
    project_id: process.env.pikamed_FIREBASE_PROJECT_ID,
    private_key_id: process.env.pikamed_FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.pikamed_FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    client_email: process.env.pikamed_FIREBASE_CLIENT_EMAIL,
    client_id: process.env.pikamed_FIREBASE_CLIENT_ID,
    auth_uri: process.env.pikamed_FIREBASE_AUTH_URI,
    token_uri: process.env.pikamed_FIREBASE_TOKEN_URI,
    auth_provider_x509_cert_url:
      process.env.pikamed_FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
    client_x509_cert_url: process.env.pikamed_FIREBASE_CLIENT_X509_CERT_URL,
    universe_domain: process.env.pikamed_FIREBASE_UNIVERSE_DOMAIN,
  }),
});
let scheduledJobs = []; // Globalde tanımla
const DATABASE_PATH = "data/pikamed.json";
router.get("/", async (req, res) => {
  res.redirect("https://pikamed.keremkk.com.tr");
});

// Log fonksiyonları
router.post("/authlog", async (req, res) => {
  const { sebep, uid, name, profilUrl } = req.body;

  // Mesaj başlığı ve rengi belirle
  const title =
    sebep === "Giriş" ? "🚪 Kullanıcı Giriş Yaptı" : "🚪 Kullanıcı Çıkış Yaptı";
  const color = sebep === "Giriş" ? 0x2ecc71 : 0xe74c3c; // Yeşil renk giriş için, kırmızı renk çıkış için

  // Embed Mesajı Tanımla
  const embed = {
    title: title,
    color: color,
    fields: [
      { name: "👤 İsim", value: name, inline: true },
      { name: "🆔 UID", value: `\`${uid}\``, inline: false },
      { name: "Sebep", value: sebep, inline: false },
    ],
    thumbnail: {
      url: profilUrl, // Kullanıcı profil fotoğrafı
    },
    footer: {
      text: "PikaMed Giriş/Çıkış Logu",
      icon_url:
        "https://cdn.glitch.global/e74d89f5-045d-4ad2-94c7-e2c99ed95318/logo.jpg?v=1737331226085",
    },
    timestamp: new Date(),
  };

  try {
    // ✅ Embed mesajını gönder
    await sendMessageToDiscord(
      `📢 Kullanıcı ${sebep === "Giriş" ? "giriş yaptı" : "çıkış yaptı"}:`,
      process.env.pikamed_authlog,
      embed
    );
  } catch (error) {
    console.error(
      "Mesaj gönderilemedi:",
      error.response ? error.response.data : error.message
    );
  }

  // Başarılı bir yanıt gönder
  res
    .status(200)
    .send(
      `${sebep === "Giriş" ? "Giriş" : "Çıkış"} işlemi başarıyla kaydedildi.`
    );
});   //uygulamaya ait giriş çıkış logu doğrulaması yok çünkü çıkış yaparken token yok
router.post("/pikamedfeedback",AuthCheck('user',"/pikamedfeedback"), async (req, res) => {
  const { sebep, message, isim, eposta, uid } = req.body;

  const embed = {
    title: "Yeni İletişim Formu Gönderildi",
    color: 0x3498db, // Mavi renk
    fields: [
      {
        name: "Nedeni",
        value: sebep || "Verilmedi",
        inline: true,
      },
      {
        name: "Mesaj",
        value: message,
        inline: false,
      },
      {
        name: "Kullanıcı Bilgileri",
        value: `İsim: ${isim}\nE-posta: ${eposta}\nUID: ${uid}`,
        inline: false,
      },
    ],
    footer: {
      text: "Yeni iletişim formu alındı",
    },
    timestamp: new Date(),
  };

  try {
    await sendMessageToDiscord("", process.env.pikamed_feedback, embed);
    res.status(200).send("Mesaj başarıyla gönderildi!");
  } catch (error) {
    console.error("Mesaj gönderilemedi:", error.message);
    res.status(500).send("Mesaj gönderilirken bir hata oluştu.");
  }
}); // uygulamadaki feedback apisi
router.post("/ai",AuthCheck('user',"/ai"), async (req, res) => {
  const {
    uid,
    message,
    targetWater,
    availableWater,
    cupSize,
    changeWaterDay,
    changeWaterClock,
    weight,
    size,
    bmi,
    bmiCategory,
    name,
    selectedLanguage,
    localTime,
    insulinPlan
  } = req.body;

  try {
    const userRecord = await firebaseAdmin.auth().getUser(uid);
    console.log("Kullanıcı doğrulandı:", userRecord.toJSON());

    const prompt = `
    Sen bir endokrinoloji uzmanı (doktor) rolündesin. Sana mesaj atan kişiler, tip 1 diyabet hastası olan bireylerdir.
    Onlarla yalnızca bir doktor gibi profesyonel bir dille, nazik ve kısa şekilde iletişim kur.

    Cevap Kuralları:
    - Sadece kullanıcının mesajındaki soruya odaklan ve onun dışına çıkma.
    - Gereksiz bilgi, tavsiye veya sohbet ekleme.
    - Yanıtlarda kısa, net ve hastayı rahatlatıcı bir üslup kullan.
    - İnsülin dozunu değerlendirirken hastanın kilosunu ve günlük su tüketimini dikkate al.
    - Sorulmadıkça farklı bir bilgi veya açıklama yapma.

    Hasta Bilgileri:
    - Günlük Su Tüketim Hedefi: ${targetWater} ml
    - Şu ana kadar İçilen Su: ${availableWater} ml
    - Bardak Boyutu: ${cupSize} ml
    - Su Takibi Yenilenme Günü/Saati: ${changeWaterDay}, ${changeWaterClock}
    - Kilo: ${weight} kg
    - Boy: ${size} cm
    - Vücut Kitle İndeksi (BMI): ${bmi} (${bmiCategory})
    - Adı: ${name}
    - Konuşma Dili: ${selectedLanguage}
    - Yerel Saat: ${localTime}

    İnsülin Kullanım Planı:
    ${JSON.stringify(insulinPlan, null, 2)}

    Kullanıcının Mesajı:
    <<${message}>>
    `;

    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${process.env.GEMINI_API_KEY}`,
      {
        contents: [{ parts: [{ text: prompt }] }],
      },
      {
        headers: { "Content-Type": "application/json" },
      }
    );

    const aiResponse =
      response.data.candidates?.[0]?.content?.parts?.[0]?.text ?? "Yanıt alınamadı.";

    // Dosya adı için timestamp ekleyelim
    const timestamp = new Date().toISOString().replace(/[:.-]/g, '_');  // Dosya isminin güvenli olması için
    const logFileName = `gemini-log-${uid}-${timestamp}.txt`;
    const logFilePath = path.join(__dirname, 'logs', logFileName);  // logs klasörüne kaydetmek daha düzenli olur

    // Prompt ve yanıtı log dosyasına yaz
    const logText = `📥 Prompt:\n${prompt}\n\n🤖 AI Yanıtı:\n${aiResponse}`;

    await  fs.promises.writeFile(logFilePath, logText);  // Asenkron yazma işlemi

    const embed = {
      title: "Gemini API Log",
      color: 3447003,
      fields: [
        {
          name: "👤 Kullanıcı",
          value: `**İsim:** \`${userRecord.displayName || "Bilinmiyor"}\`\n**UID:** \`${uid || "Bilinmiyor"}\`\n**E-Posta:** \`${userRecord.email || "Bilinmiyor"}\``,
        },
      ],
      thumbnail: { url: userRecord.photoURL },
      timestamp: new Date(),
    };

    await sendMessageToDiscord(
      "Gemini yanıtı ve prompt ektedir.",
      process.env.pikamed_ailog,
      embed,
      logFilePath
    );

    // Log dosyasını Discord'a gönderdikten sonra silebiliriz
    await  fs.promises.unlink(logFilePath);  // Asenkron silme işlemi

    res.json({ aiResponse });
  } catch (err) {
    if (err.code === "auth/user-not-found") {
      return res.status(403).json({ error: "Geçersiz kullanıcı ID'si" });
    }
    console.error(err.response?.data || err.message);
    res.status(500).json({ error: "Gemini API hatası" });
  }
});  // yapay zeka apisi

// Admin Panel
router.post("/add-doctor",AuthCheck('admin',"/add-doctor"), async (req, res) => {
  const { uid, doctorEmail } = req.body;
const admin = await firebaseAdmin.auth().getUser(uid);

  try {
    // Doktorun e-posta adresini kullanarak kullanıcıyı al
    const userRecord = await firebaseAdmin.auth().getUserByEmail(doctorEmail);

    // Kullanıcıya "doctor" rolünü ata
    await firebaseAdmin
      .auth()
      .setCustomUserClaims(userRecord.uid, { role: "doctor" });

    return res.status(200).json({
      success: true,
      message: "Doktor rolü başarıyla atandı!",
    });
  } catch (error) {
    return res.status(404).json({
      success: false,
      message: `Hata: ${error.message}`,
    });
  }
}); // admin panel doktor ekleme
router.post("/delete-doctor",AuthCheck('admin',"/delete-doctor"), async (req, res) => {
  const { uid, doctorEmail } = req.body;
  const admin = await firebaseAdmin.auth().getUser(uid);

  try {
    // Silinecek doktoru Firebase'den al
    const userRecord = await firebaseAdmin.auth().getUserByEmail(doctorEmail);

    // Kullanıcının özel rolünü "doctor" olarak ayarla
    await firebaseAdmin
      .auth()
      .setCustomUserClaims(userRecord.uid, { role: null });

    return res.status(200).json({
      success: true,
      message: "Doktor başarıyla silindi!",
    });
  } catch (error) {
    return res.status(404).json({
      success: false,
      message: `Hata: ${error.message}`,
    });
  }
}); // admin panel doktor silme

// Data Fonksiyonları
router.get("/get-doctors",AuthCheck('admin',"/get-doctors"), async (req, res) => {
  try {
    // Firebase Authentication kullanıcılarını listele
    const listUsersResult = await firebaseAdmin.auth().listUsers();
    const doctors = listUsersResult.users
      .filter((user) => user.customClaims?.role === "doctor") // Sadece doktor rolüne sahip kullanıcıları al
      .map((user) => ({
        email: user.email,
        fullName: user.displayName, // Kullanıcı adı
      }));
    return res.status(200).json({
      success: true,
      doctors,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: `Hata: ${error.message}`,
    });
  }
}); // doktor rolündeki kişileri getirme
router.get("/get-admins", AuthCheck("admin","/get-admins"), async (req, res) => {
  try {
    const listUsersResult = await firebaseAdmin.auth().listUsers();

    const admins = listUsersResult.users
      .filter((user) => user.customClaims?.role === "admin") // sadece admin
      .map((user) => ({
        email: user.email,
        fullName: user.displayName || "İsimsiz Admin",
      }));

    return res.status(200).json({
      success: true,
      admins,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: `Hata: ${error.message}`,
    });
  }
}); // admin rolündeki kişileri getirme
router.get("/get-users",AuthCheck('doctor',"/get-users"), async (req, res) => {
  try {
    // Firebase Authentication kullanıcılarını listele
    const listUsersResult = await firebaseAdmin.auth().listUsers();
    const users = listUsersResult.users.map((user) => ({
      email: user.email,
      displayName: user.providerData[0]?.displayName, // Kullanıcı adı
      uid: user.uid,
    }));

    return res.status(200).json({
      success: true,
      patients: users, // Tüm kullanıcıları göster
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: `Hata: ${error.message}`,
    });
  }
}); // kayıtlı tüm kişileri getirme admin ve doktor dahil
router.post("/userdata", AuthCheck('user',"/userdata"), async (req, res) => {
  const { uid } = req.body;
  const userToken = req.user; // AuthCheck middleware'inde zaten req.user atanmış oluyor
  // UID eşleşmiyorsa ve kullanıcı yetkisi düşükse işlemi engelle
  if (uid !== userToken.uid) {
    const roleToLevel = {
      user: 0,
      doctor: 1,
      admin: 3,
      superadmin: 5
    };
    const userRoleLevel = roleToLevel[userToken.role] || 0;

    if (userRoleLevel < roleToLevel["doctor"]) {
      return res.status(403).json({ error: "Bu kullanıcıya ait verilere erişim yetkiniz yok." });
    }
  }

  try {
    const { channelId } = await checkUser(uid);
    // Discord kanal verilerini al
    const channelResponse = await axios.get(
      `https://discord.com/api/v10/channels/${channelId}`,
      {
        headers: { Authorization: `Bot ${process.env.bot_token}` },
      }
    );
    const channelData = channelResponse.data;

    // Kategori kontrolü
    if (
      !channelData.parent_id ||
      channelData.parent_id !== process.env.pikamed_kullanicicategory
    ) {
      return res.status(403).json({ hata: "Bu kanalın bulunduğu kategoride işlem yapılamaz." });
    }

    // Son mesajı al
    const messagesResponse = await axios.get(
      `https://discord.com/api/v10/channels/${channelId}/messages?limit=1`,
      {
        headers: { Authorization: `Bot ${process.env.bot_token}` },
      }
    );

    if (messagesResponse.data.length > 0) {
      const lastMessage = messagesResponse.data[0];

      // Dosya varsa gönder
      if (lastMessage.attachments && lastMessage.attachments.length > 0) {
        const fileUrl = lastMessage.attachments[0].url;
        const fileResponse = await axios.get(fileUrl, {
          responseType: "stream",
        });

        res.setHeader("Content-Type", fileResponse.headers["content-type"]);
        return fileResponse.data.pipe(res);
      } else {
        return res.status(404).json({ hata: "Mesajda dosya bulunamadı." });
      }
    } else {
      return res.status(404).json({ hata: "Kanalda hiç mesaj yok." });
    }
  } catch (error) {
    console.error("Hata:", error.message);
    res.status(500).json({ hata: "Sunucu hatası: " + error.message });
  }
}); // kullanıcın datasını veritabanından çekme
router.post("/info", AuthCheck('user', "/info"), async (req, res) => {
  const {
    message,
    name,
    uid,
    photoURL,
    version,
    country,
    selectedLanguage,
    targetWater,
    availableWater,
    cupSize,
    changeWaterClock,
    changeWaterDay,
    InsulinListData,
    size,
    weight,
    changeWeightClock,
    bmiCategory,
    bmi,
    notificationRequest,
  } = req.body;
 const userToken = req.user;
  
  const logData = {
    name,
    uid,
    photoURL,
    selectedLanguage,
    targetWater,
    availableWater,
    cupSize,
    changeWaterClock,
    changeWaterDay,
    InsulinListData,
    size,
    weight,
    changeWeightClock,
    bmiCategory,
    bmi,
    notificationRequest,
  };
  
  const fileName = `log_${uid}.json`;
  const filePath = path.join(__dirname, "../data", fileName);
  const { channelId } = await checkUser(userToken.uid);
  
  const embed = {
    title: "📜 Yeni Log Mesajı",
    color: 3447003,
    fields: [
      {
        name: "👤 Kullanıcı",
        value: `**İsim:** ${name || "Bilinmiyor"}\n**UID:** \`${uid || "Bilinmiyor"}\``,
        inline: false,
      },
      { name: "🌍 Ülke", value: country || "Bilinmiyor", inline: true },
      { name: "📊 Sürümü", value: version || "Bilinmiyor", inline: true },
    ],
    thumbnail: {
      url:
        photoURL ||
        "https://cdn.glitch.global/e74d89f5-045d-4ad2-94c7-e2c99ed95318/2815428.png?v=1738114346363",
    },
    timestamp: new Date(),
  };

  try {
    fs.writeFileSync(filePath, JSON.stringify(logData, null, 2));
    
    await sendFileToDiscord(filePath, channelId);
    await sendMessageToDiscord(null, process.env.pikamed_info, embed);

    // ✅ Dosyayı gönderme işlemi tamamlandıktan sonra sil
    await fs.promises.unlink(filePath);

    return res.status(200).json({
      success: true,
      message: "✅ Log mesajı başarıyla kaydedildi, gönderildi ve silindi!",
    });
  } catch (error) {
    console.error("❌ Hata oluştu:", error);

    try {
      await sendMessageToDiscord(null, process.env.pikamed_info, embed);
      return res.status(200).json({
        success: true,
        message: "✅ Log mesajı kaydedilemedi ancak mesaj gönderildi!",
      });
    } catch (innerError) {
      console.error("❌ Discord mesajı da gönderilemedi:", innerError);
      return res.status(500).json({
        success: false,
        message: "❌ Log ve mesaj gönderilemedi.",
      });
    }
  }
});  // veritabanına kullanıcı verisi ekleme

// E-Mail fonksiyonları
router.post("/send-notification", AuthCheck('admin', "/send-notification"), async (req, res) => {
  const { message, target, targetId, senderUid, title } = req.body;

  if (!message || !target || !senderUid || !title) {
    return res.status(400).json({ error: "Eksik alanlar mevcut" });
  }

  console.log("📧 E-posta bildirimi başlatıldı:", { message, title, target, targetId });

  try {
    let recipients = [];

    if (target === 'all' || target === 'doctor' || target === 'user') {
      let allUsers = [];
      let pageToken;

      do {
        const result = await firebaseAdmin.auth().listUsers(1000, pageToken);
        const usersWithEmail = result.users.filter(u => u.email);
        allUsers.push(...usersWithEmail);
        pageToken = result.pageToken;
      } while (pageToken);

      if (target === 'all') {
        recipients = allUsers;
      } else {
        recipients = allUsers.filter(u => u.customClaims?.role === target);
      }

    } else if (target === 'specific') {
      const user = await firebaseAdmin.auth().getUser(targetId);
      if (!user.email) {
        return res.status(404).json({ error: "Kullanıcının e-posta adresi bulunamadı." });
      }
      recipients = [user];
    } else {
      return res.status(400).json({ error: "Geçersiz hedef tipi." });
    }

    const sendResults = await Promise.allSettled(
      recipients.map(r => sendEmail(r.email, title, message))
    );

    const sentCount = sendResults.filter(r => r.status === "fulfilled").length;

    console.log(`✅ ${sentCount} kullanıcıya e-posta gönderildi.`);

    return res.status(200).json({ success: true, sentCount });

  } catch (err) {
    console.error("❌ E-posta gönderimi başarısız:", err);
    return res.status(500).json({ error: "E-posta gönderimi sırasında bir hata oluştu." });
  }
});
router.post("/send-warning",AuthCheck('doctor',"/send-warning"), async (req, res) => {
  try {
    const { doktorUid, patientUid } = req.body;

    // Firebase Admin SDK ile UID'ye göre rol doğrulama
    const doctor = await firebaseAdmin.auth().getUser(doktorUid);
    const patient = await firebaseAdmin.auth().getUser(patientUid);
    if (doctor.customClaims?.role !== "doctor") {
      return res
        .status(401)
        .json({ success: false, error: "Yetkisiz erişim!" });
    }

    const doktoradi =
      doctor.providerData[0]?.displayName || "Bilinmeyen Doktor";
    const hastaadi = patient.providerData[0]?.displayName || "Bilinmeyen Hasta";
    const tarihSaat = new Date().toLocaleString("tr-TR");

    const htmlContent = `<!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Önemli Uyarı: Hasta Bilgilerine Erişim Sağlandı</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #121212; color: #ddd; }
            .container { max-width: 600px; margin: 20px auto; background-color: #1e1e2e; padding: 20px; border-radius: 10px; }
            .header { text-align: center; padding: 20px; }
            h1 { font-size: 22px; color: #f8f8f2; }
            p { font-size: 16px; line-height: 1.5; }
            .details { background-color: #282a36; padding: 10px; border-radius: 5px; }
            .details strong { color: #ff79c6; }
            .footer { margin-top: 20px; text-align: center; font-size: 14px; color: #888; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Konu: Önemli Uyarı: Hasta Bilgilerine Erişim Sağlandı</h1>
            <p>Merhaba,</p>
            <p>Bu e-posta, <strong>${doktoradi}</strong> tarafından <strong>${hastaadi}</strong> adlı hastanın bilgilerine erişildiğini bildirmek amacıyla gönderilmiştir.</p>
            <div class="details">
                <p><strong>Doktor:</strong> ${doktoradi}</p>
                <p><strong>Hasta:</strong> ${hastaadi}</p>
                <p><strong>Tarih ve Saat:</strong> ${tarihSaat}</p>
            </div>
            <p>Eğer haberiniz yoksa veya yetkisiz bir erişim olduğunu düşünüyorsanız, lütfen hemen bizimle iletişime geçin.</p>
            <div class="footer">
                <p>Sağlıklı günler dileriz,<br>PikaMed Destek Ekibi</p>
            </div>
        </div>
    </body>
    </html>`;

    // Mailjet API isteği
    await mailjet.post("send", { version: "v3.1" }).request({
      Messages: [
        {
          From: { Email: "PikaMed@geogame.can.re", Name: "PikaMed" },
          To: [{ Email: patient.email, Name: "Alıcı" }],
          Subject: "Güvenlik Uyarısı",
          HTMLPart: htmlContent,
        },
      ],
    });

    // Discord'a log gönder
    const discordEmbed = {
      title: "Hasta Bilgilerine Erişim Uyarısı",
      color: 16711680, // Kırmızı renk
      fields: [
        {
          name: "Doktor Bilgileri",
          value: `**İsim:** ${doktoradi}\n**UID:** \`${doktorUid}\``,
          inline: false,
        },
        {
          name: "Hasta Bilgileri",
          value: `**İsim:** ${hastaadi}\n**UID:** \`${patientUid}\``,
          inline: false,
        },
      ],
      timestamp: new Date(),
    };

    await sendMessageToDiscord(
      "",
      process.env.pikamed_bakilanhastalog,
      discordEmbed
    );

    res.json({
      success: true,
      message: "E-posta ve Discord log başarıyla gönderildi!",
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});  // doktor kullanıcın verisine bakınca uyarı epostası gönderme
router.post('/notificationInfo',AuthCheck('user','/notificationInfo'), async (req, res) => {
  const { uid, name, email, InsulinListData, notificationRequest } = req.body;

  const dataDirectory = path.join(__dirname, '../data');
  const filePath = path.join(dataDirectory, 'notificationInfo.json'); // Burada dosya adı belirlenmiş

  try {
    // getFileUrl fonksiyonundan gelen URL ile dosyayı indiriyoruz
    const fileUrl = await getFileUrl(process.env.pikamed_notification);

    // URL'den dosya verisini indir
    const response = await axios.get(fileUrl, { responseType: 'arraybuffer' });
    
    let existingData = {};

    // İndirilen veriyi dosyaya kaydedelim
    const downloadPath = path.join(dataDirectory, 'temp_notificationInfo.json');
    fs.writeFileSync(downloadPath, response.data);

    if (fs.existsSync(downloadPath)) {
      // Dosya var, o zaman mevcut dosyayı yükleyelim
      existingData = JSON.parse(fs.readFileSync(downloadPath, 'utf-8'));
    } else {
      existingData.users = [];
    }

    // Kullanıcıyı mevcut veriye ekle
    const newUser = {
      uid,
      name,
      email,
      notificationRequest,
      InsulinListData: InsulinListData || []
    };

    // UID'ye göre kontrol et, aynı UID varsa güncelle, yoksa ekle
    const userIndex = existingData.users.findIndex(user => user.uid === uid);
    
    if (userIndex !== -1) {
      // UID mevcutsa, mevcut kullanıcıyı güncelle
      existingData.users[userIndex] = newUser;
    } else {
      // Yeni kullanıcı ekle
      existingData.users.push(newUser);
    }

    // Veriyi JSON dosyasına kaydet
    fs.writeFileSync(downloadPath, JSON.stringify(existingData, null, 2));

    // Dosya yolunu Discord'a gönderme
    await sendFileToDiscord(downloadPath, process.env.pikamed_notification);

    // İşlem tamamlandıktan sonra geçici dosyayı sil
    fs.unlinkSync(downloadPath);  // Dosyayı sil

    createCronJobs();
    res.status(200).json({
      success: true,
      message: "Veri başarıyla kaydedildi ve güncellendi!",
    });

  } catch (error) {
    console.error('Hata:', error);
    res.status(500).json({
      success: false,
      message: 'Veri kaydedilemedi veya dosya indirilemedi.',
    });
  }
});  // bildirim listesine hatırlatma tarihlerini ve bildirim tercihini gönderme
router.get('/unsubscribe', async (req, res) => {
  const { uid } = req.query;

  if (!uid) {
    return res.status(400).json({ success: false, message: 'UID eksik' });
  }

  try {
    const downloadPath = path.join(__dirname, 'temporaryNotificationInfo.json');
    
    // Dosyayı indir
    await downloadFile(await getFileUrl(process.env.pikamed_notification), downloadPath);

    // JSON dosyasındaki veriyi oku
    const jsonData = await readFileAsync(downloadPath);
    const users = jsonData.users;

    // Kullanıcıyı bul ve notificationRequest değerini false yap
    const userIndex = users.findIndex(user => user.uid === uid);

    if (userIndex !== -1) {
      users[userIndex].notificationRequest = false;

      // JSON dosyasını güncelle
      await fs.promises.writeFile(downloadPath, JSON.stringify({ users }, null, 2));

      // Güncellenmiş dosyayı tekrar yükle
      await sendFileToDiscord(downloadPath, process.env.pikamed_notification);

      // Geçici dosyayı sil
      fs.unlinkSync(downloadPath);

      // Dinamik HTML sayfasını kullanıcıya gönder
      const htmlContent = `
        <!DOCTYPE html>
        <html lang="tr">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Bildirim İptali</title>
          <style>
            body {
              font-family: Arial, sans-serif;
              background-color: #f4f7f6;
              color: #333;
              padding: 20px;
            }
            .container {
              max-width: 600px;
              margin: 0 auto;
              background-color: #fff;
              padding: 30px;
              border-radius: 8px;
              box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            }
            h1 {
              text-align: center;
              color: #3498db;
            }
            p {
              font-size: 16px;
              line-height: 1.6;
            }
            .alert {
              background-color: #f8d7da;
              color: #721c24;
              padding: 10px;
              border-radius: 5px;
              margin-top: 20px;
            }
            .footer {
              margin-top: 30px;
              text-align: center;
              font-size: 14px;
              color: #aaa;
            }
            .link {
              color: #3498db;
              text-decoration: none;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Bildirim İptali Başarılı</h1>
            <p>Artık insülin aşı hatırlatmalarını almayacaksınız.</p>
            
            <div class="alert">
              <strong>Not:</strong> Uygulamanızı yeniden açtığınızda bildirimler tekrar aktif hale gelecektir. Bildirim almak istemiyorsanız, uygulamayı kullanmayınız.
            </div>
            
            <div class="footer">
              <p>Herhangi bir sorun yaşarsanız, bizimle iletişime geçebilirsiniz.</p>
              <p>© 2025 Pikamed. Tüm hakları saklıdır.</p>
            </div>
          </div>
        </body>
        </html>
      `;

      res.status(200).send(htmlContent);  // Dinamik HTML sayfasını kullanıcıya gönder
    } else {
      res.status(404).json({ success: false, message: 'Kullanıcı bulunamadı' });
    }
  } catch (error) {
    console.error('Hata:', error);
    res.status(500).json({ success: false, message: 'Bir hata oluştu' });
  }
});  // e-posta aboneliğinden çıkma


// Superadmin Erişimi 
router.get('/superadmin-access', AuthCheck('superadmin','/superadmin-access'), (req, res) => {
  res.json({ access: true });
});

// Admin Erişim Kontrolleri
router.get('/admin-access', AuthCheck('admin','/admin-access'), (req, res) => {
  res.json({ access: true });
});

// Doktor Erişimi 
router.get('/doctor-access', AuthCheck('doctor','/doctor-access'), (req, res) => {
  res.json({ access: true });
});

// Normal Kullanıcı Erişimi
router.get('/user-access', AuthCheck('user','/user-access'), (req, res) => {
  res.json({ access: true });
});

//fonksiyonlar
const readFileAsync = async (filePath) => {
  try {
    const data = await fs.promises.readFile(filePath, "utf8");
    return JSON.parse(data);
  } catch (error) {
    if (error.code === "ENOENT") {
      console.warn(`${filePath} dosyası bulunamadı, yeni dosya oluşturulacak.`);
      return { users: [] }; // Varsayılan boş kullanıcı listesi döndür
    }
    throw error; // Diğer hataları yükselt
  }
};
const sendFileToDiscord = async (filePath, channelId) => {
  const file = fs.createReadStream(filePath);
  const formData = new FormData();
  formData.append("file", file);

  const response = await axios.post(
    `https://discord.com/api/v10/channels/${channelId}/messages`,
    formData,
    {
      headers: {
        Authorization: `Bot ${process.env.bot_token}`,
        "Content-Type": "multipart/form-data",
        ...formData.getHeaders(),
      },
    }
  );
  console.log("Dosya başarıyla gönderildi!");
};
const sendMessageToDiscord = async (message, channelId, embed = null, filePath = null) => {
  if (!channelId || typeof channelId !== "string" || channelId.trim() === "") {
    console.error("Geçersiz kanal kimliği.");
    throw new Error("Geçersiz kanal kimliği.");
  }

  try {
    // Dosya varsa multipart/form-data ile gönder
    if (filePath) {
      const form = new FormData();
      form.append("payload_json", JSON.stringify({
        content: message,
        embeds: embed ? [embed] : [],
      }));
      form.append("file", fs.createReadStream(filePath));

      const response = await axios.post(
        `https://discord.com/api/v10/channels/${channelId}/messages`,
        form,
        {
          headers: {
            Authorization: `Bot ${process.env.bot_token}`,
            ...form.getHeaders(), // multipart header'ları dahil et
          },
        }
      );
      console.log("Mesaj ve dosya başarıyla gönderildi!");
    } else {
      // Dosya yoksa klasik JSON POST
      const response = await axios.post(
        `https://discord.com/api/v10/channels/${channelId}/messages`,
        {
          content: message,
          embeds: embed ? [embed] : [],
        },
        {
          headers: {
            Authorization: `Bot ${process.env.bot_token}`,
            "Content-Type": "application/json",
          },
        }
      );
      console.log("Mesaj başarıyla gönderildi!");
    }
  } catch (error) {
    console.error("Mesaj gönderilemedi:", error.response?.data || error.message);
  }
};
async function downloadFile(fileUrl, filePath) {
  return new Promise((resolve, reject) => {
    https
      .get(fileUrl, (res) => {
        if (res.statusCode !== 200) {
          // Eğer HTTP yanıtı 200 değilse, hata olarak değerlendir.
          return reject(
            new Error(`Dosya indirilemedi. HTTP Durumu: ${res.statusCode}`)
          );
        }

        const fileStream = fs.createWriteStream(filePath);
        res.pipe(fileStream);

        fileStream.on("finish", () => {
          resolve(filePath); // Dosya başarıyla indirildi.
        });

        fileStream.on("error", (error) => {
          reject(error); // Yazma sırasında hata oluşursa
        });
      })
      .on("error", (error) => {
        reject(error); // HTTPS isteğinde hata oluşursa
      });
  }).catch(async (error) => {
    console.error("Dosya indirilemedi", error.message);
  });
}
async function getFileUrl(odaId) {
  try {
    const response = await axios.get(
      `https://discord.com/api/v10/channels/${odaId}/messages`,
      {
        headers: {
          Authorization: `Bot ${process.env.bot_token}`,
        },
        params: {
          limit: 1,
        },
      }
    );

    if (response.data && response.data.length > 0) {
      const lastMessage = response.data[0]; // İlk mesaj
      if (lastMessage.attachments && lastMessage.attachments.length > 0) {
        const fileUrl = lastMessage.attachments[0].url;
        //console.log("Dosya URL'si:", fileUrl);
        return fileUrl; // Dosya URL'sini döndür
      } else {
        throw new Error("Mesajda dosya yok.");
      }
    } else {
      throw new Error("Mesaj bulunamadı.");
    }
  } catch (error) {
    console.error("Mesaj alınırken hata oluştu:", error.message);
    throw error; // Hata durumunda tekrar fırlat
  }
}
function insulinAsiHatirlatma(email, name, appearanceTime, uid) {
  const unsubscribeLink = `https://keremkk.glitch.me/pikamed/unsubscribe?uid=${uid}`;
  
  const request = mailjet
    .post("send", { 'version': 'v3.1' })
    .request({
      "Messages": [
        {
          "From": { Email: "PikaMed@geogame.can.re", Name: "PikaMed" },
          "To": [
            {
              "Email": email,
              "Name": name
            }
          ],
          "Subject": "İnsülin Aşı Zamanı Hatırlatması",
          "HTMLPart": `
            <html>
              <body style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f2f4f6; padding: 30px;">
                <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); overflow: hidden;">
                  <div style="background-color: #3498db; padding: 20px; text-align: center; color: #ffffff;">
                    <h1 style="margin: 0; font-size: 24px;">İnsülin Aşı Hatırlatıcısı</h1>
                  </div>
                  <div style="padding: 30px;">
                    <h2 style="color: #2c3e50;">Merhaba ${name},</h2>
                    <p style="font-size: 16px; color: #555; line-height: 1.6; margin-top: 10px;">
                      Bu bir nazik hatırlatmadır. İnsülin aşınızı 
                      <strong style="color: #e74c3c;">${appearanceTime}</strong> tarihinde olmanız gerekmektedir.
                    </p>
                    <p style="font-size: 14px; color: #7f8c8d; margin-top: 20px;">
                      Sağlıklı günler dileriz.<br/>
                      <strong>Pikamed Ekibi</strong>
                    </p>
                    <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                    <p style="font-size: 12px; color: #b0b0b0; text-align: center;">
                      Bildirim almak istemiyorsanız, lütfen <a href="${unsubscribeLink}">buraya tıklayın</a> ve insülin aşı takviminizi kaldırın.
                    </p>
                  </div>
                </div>
                <div style="text-align: center; font-size: 11px; color: #aaa; margin-top: 20px;">
                  © 2025 Pikamed. Tüm hakları saklıdır.
                </div>
              </body>
            </html>
          `
        }
      ]
    });

 request
    .then((result) => {
      console.log("✅ E-posta başarıyla gönderildi:", result.body);

      // Discord'a başarı mesajı
      const successMessage = {
        title: "E-posta Başarıyla Gönderildi",
        color: 3066993, // Yeşil renk
        fields: [
          {
            name: "Gönderim Durumu",
            value: `E-posta başarıyla gönderildi: ${name} (${email}) - ${appearanceTime}`,
            inline: false,
          },
        ],
      };

      sendMessageToDiscord("", process.env.pikamed_notificationlog,successMessage,);
    })
    .catch((err) => {
      console.error("❌ E-posta gönderim hatası:", err.statusCode, err);

      // Discord'a hata mesajı
      const errorMessage = {
        title: "E-posta Gönderimi Hatası",
        color: 15158332, // Kırmızı renk
        fields: [
          {
            name: "Hata Bilgisi",
            value: `E-posta gönderimi başarısız: ${name} (${email}) - ${appearanceTime}. Hata: ${err.message}`,
            inline: false,
          },
        ],
      };

      sendMessageToDiscord("", process.env.pikamed_notificationlog,errorMessage);
    });
}
const createCronJobs = async () => {
  const downloadPath = path.join(__dirname, 'temporaryNotificationInfo.json');

  try {
    // Önceki job'ları temizle
    scheduledJobs.forEach(job => job.stop());
    scheduledJobs = [];

    const fileUrl = await getFileUrl(process.env.pikamed_notification);
    await downloadFile(fileUrl, downloadPath);

    const jsonData = await readFileAsync(downloadPath);
    const users = jsonData.users;

    users.forEach(user => {
      if (user.notificationRequest) {
        user.InsulinListData.forEach(insulin => {
          const { hour, minute, titleTxt } = insulin;
          const correctedHour = (hour - 3 + 24) % 24;
          const cronTime = `${minute} ${correctedHour} * * *`;

          try {
            const job = cron.schedule(cronTime, () => {
              insulinAsiHatirlatma(user.email, user.name, titleTxt, user.uid);
            });

            scheduledJobs.push(job); // Kaydet
            console.log(`Cron job kuruldu: ${titleTxt} - ${hour}:${minute}`);
          } catch (error) {
            console.error(`Cron job kurulurken hata oluştu: ${error.message}`);
          }
        });
      }
    });

    fs.unlinkSync(downloadPath);
  } catch (error) {
    console.error('Dosya indirilirken veya okurken hata oluştu:', error);
  }
};
async function sendEmail(to, subject, htmlContent) {
  try {
    const result = await mailjet
      .post("send", { version: "v3.1" })
      .request({
        Messages: [
          {
            From: {
              Email: "pikamed@geogame.can.re", // kendi alan adınızı kullanın
              Name: "PikaMed",
            },
            To: [
              {
                Email: to,
              },
            ],
            Subject: subject,
            HTMLPart: htmlContent,
          },
        ],
      });

    console.log(`📨 E-posta gönderildi -> ${to}, Mailjet ID: ${result.body.Messages[0].To[0].MessageID}`);
  } catch (error) {
    console.error(`❌ E-posta gönderimi başarısız (${to}):`, error.message || error);
    throw error;
  }
}
async function createChannelpikamed(channelName) {
    const guildId = process.env.sunucuid;
    const categoryId = process.env.pikamed_kullanicicategory;
    const botToken = process.env.bot_token;

    if (!guildId || !categoryId || !botToken) {
        console.error("❌ Gerekli environment değişkenleri eksik!");
        return null;
    }

    const url = `https://discord.com/api/v10/guilds/${guildId}/channels`;

    const body = {
        name: channelName,
        type: 0, // 0 = GUILD_TEXT
        parent_id: categoryId
    };

    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Authorization': `Bot ${botToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
    });

    if (!response.ok) {
        const error = await response.json();
        console.error("❌ Kanal oluşturulamadı:", error);
        return null;
    }

    const data = await response.json();
    console.log(`✅ Kanal oluşturuldu: ${data.name} (ID: ${data.id})`);
    return data.id;
}
async function checkUser(uid) {
  if (!uid) {
    throw new Error("❌ UID gereklidir.");
  }

  try {
    const userRecord = await firebaseAdmin.auth().getUser(uid);

    const userName =
      userRecord.providerData[0]?.displayName || `User_${uid.substring(0, 5)}`;

    const fileUrl = await getFileUrl(process.env.pikamed_kullaniciidlist);

    try {
      await downloadFile(fileUrl, DATABASE_PATH);
      console.log("Dosya başarıyla indirildi:", DATABASE_PATH);
    } catch (error) {
      throw new Error("❌ Dosya indirilemedi.");
    }

    let db = await fs.promises.readFile(DATABASE_PATH, 'utf8');
    db = JSON.parse(db);
    
    if (!db.users) {
      db.users = {};
    }

    if (db.users[uid]) {
      return {
        success: true,
        isNew: false,
        uid,
        channelId: db.users[uid].channelID,
      };
    } else {
      const newChannelID = await createChannelpikamed(userName);
      db.users[uid] = { channelID: newChannelID };

      console.log(
        `🆕 Yeni kullanıcı eklendi: UID=${uid}, KanalID=${newChannelID}, Kullanıcı Adı=${userName}`
      );

      await fs.promises.writeFile(
        DATABASE_PATH,
        JSON.stringify(db, null, 2),
        "utf8"
      );

      sendFileToDiscord(DATABASE_PATH, process.env.pikamed_kullaniciidlist);

      return {
        success: true,
        isNew: true,
        uid,
        channelId: newChannelID,
      };
    }
  } catch (error) {
    return {
      success: false,
      message: error.message || "❌ Bilinmeyen bir hata oluştu.",
    };
  }
}
async function manageAdminRoleByEmail(email, action) {
  try {
    // E-posta adresi ile kullanıcıyı bul
    const userRecord = await firebaseAdmin.auth().getUserByEmail(email);

    // Eğer action 1 ise admin rolü ekle, 0 ise admin rolünü sil
    if (action === 1) {
      // Admin rolü ekle
      await firebaseAdmin.auth().setCustomUserClaims(userRecord.uid, { role: 'admin' });
      console.log(`Admin rolü başarıyla ${email} kullanıcısına eklendi.`);
    } else if (action === 0) {
      // Admin rolünü sil
      await firebaseAdmin.auth().setCustomUserClaims(userRecord.uid, { role: '' });
      console.log(`Admin rolü başarıyla ${email} kullanıcısından silindi.`);
    } else {
      console.log('Geçersiz işlem. Lütfen 1 (ekle) veya 0 (sil) girin.');
    }
  } catch (error) {
    console.error('Admin rolü eklenirken/silinirken hata oluştu:', error);
  }
} // admin rolünü yönetme
function AuthCheck(requiredRole, functionName) {
  let embed;

  function roleToLevel(role) {
    const roles = {
      'user': 0,
      'doctor': 1,
      'admin': 3,
      'superadmin': 5
    };
    return roles[role] || 0;
  }

  return async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized: No token' });
    }

    const idToken = authHeader.split('Bearer ')[1];

    try {
      const decodedToken = await firebaseAdmin.auth().verifyIdToken(idToken);
      req.user = decodedToken;

      const userRole = req.user.role;
      if (!userRole) {
        await firebaseAdmin.auth().setCustomUserClaims(req.user.uid, { role: 'user' });
        req.user.role = 'user';
        console.log(`Kullanıcı ${req.user.uid} için rol 'user' olarak güncellendi.`);
      }

      const superAdminUid = 'HJZGLEgh1scqmChOj3Pq2eg7QhR2';

      // Eğer süper admin erişiyorsa, her şeye izin verilir
      const isSuperAdmin = req.user.uid === superAdminUid;
      const userRoleLevel = roleToLevel(req.user.role);
      const requiredRoleLevel = typeof requiredRole === 'number' ? requiredRole : roleToLevel(requiredRole);

      if (!isSuperAdmin && userRoleLevel < requiredRoleLevel) {
        embed = {
          title: "İzinsiz Erişim Denemesi",
          description: `${functionName} - Rol kontrolü başarısız`,
          fields: [
            {
              name: "Kişi Bilgileri",
              value: `**İsim:** ${req.user.name || 'Bilinmiyor'}\n**UID:** \`${req.user.uid}\`\n**Mevcut İzin:** ${req.user.role}\n**Gerekli İzin:** ${requiredRole}`,
              inline: false,
            },
          ],
          thumbnail: { url: req.user?.photoUrl || '' },
          color: 0xff0000,
          timestamp: new Date(),
        };
        sendMessageToDiscord("İzinsiz Giriş Denemesi", process.env.pikamed_endpoint_failed, embed);
        return res.status(403).json({ error: `Forbidden: You need a role level of ${requiredRoleLevel} or higher` });
      }

      embed = {
        title: "Başarılı Giriş",
        description: `${functionName} - Giriş başarılı`,
        fields: [
          {
            name: "Kişi Bilgileri",
            value: `**İsim:** ${req.user.name || 'Bilinmiyor'}\n**UID:** \`${req.user.uid}\`\n**Mevcut İzin:** ${req.user.role}\n**Gerekli İzin:** ${requiredRole}`,
            inline: false,
          },
        ],
        thumbnail: { url: req.user?.photoUrl || '' },
        color: 0x00ff00,
        timestamp: new Date(),
      };
      sendMessageToDiscord("Başarılı Giriş", process.env.pikamed_endpoint_success, embed);

      next();
    } catch (error) {
      console.error('Token doğrulama hatası:', error);
      sendMessageToDiscord(`yanlış token geldi: ${error}`, process.env.pikamed_endpoint_failed);
      res.status(401).json({ error: 'Invalid token' });
    }
  };
}

module.exports = {
  router,
  createCronJobs,
};