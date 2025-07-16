const express = require("express");
const axios = require("axios");
const https = require("https");
const fs = require("fs");
const FormData = require("form-data");
const router = express.Router();

// yakında kaldırılcak

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
const updateDatabase = async (userData) => {
  try {
    const db = await readFileAsync("data/geogame.json");

    // Kullanıcı adı Misafir ise ekleme yapılmasın
    if (userData.name === "Misafir") {
      console.log(`Misafir kullanıcı adıyla işlem yapılmaz: ${userData.name}`);
      return;
    }

    const userIndex = db.users.findIndex((user) => user.uid === userData.uid);

    if (userIndex !== -1) {
      // Aynı uid'ye sahip kullanıcı bulundu

      // Kullanıcıyı güncelle
      db.users[userIndex] = {
        name: userData.name,
        profilurl: userData.profilurl,
        uid: userData.uid,
        puan: userData.toplampuan,
        mesafedogru: userData.mesafedogru,
        mesafeyanlis: userData.mesafeyanlis,
        bayrakdogru: userData.bayrakdogru,
        bayrakyanlis: userData.bayrakyanlis,
        baskentdogru: userData.baskentdogru,
        baskentyanlis: userData.baskentyanlis,
        mesafepuan: userData.mesafepuan,
        bayrakpuan: userData.bayrakpuan,
        baskentpuan: userData.baskentpuan,
      };
      await fs.promises.writeFile(
        "data/geogame.json",
        JSON.stringify(db, null, 2),
        "utf8"
      );
      console.log(
        `Puan güncellendi: ${userData.name} - ${userData.toplampuan}`
      );
    } else {
      // Yeni kullanıcıyı ekle
      db.users.push({
        name: userData.name,
        uid: userData.uid,
        profilurl: userData.profilurl,
        puan: userData.toplampuan,
        mesafedogru: userData.mesafedogru,
        mesafeyanlis: userData.mesafeyanlis,
        bayrakdogru: userData.bayrakdogru,
        bayrakyanlis: userData.bayrakyanlis,
        baskentdogru: userData.baskentdogru,
        baskentyanlis: userData.baskentyanlis,
        mesafepuan: userData.mesafepuan,
        bayrakpuan: userData.bayrakpuan,
        baskentpuan: userData.baskentpuan,
      });
      await fs.promises.writeFile(
        "data/geogame.json",
        JSON.stringify(db, null, 2),
        "utf8"
      );
      console.log(
        `Yeni kullanıcı eklendi: ${userData.name} - ${userData.toplampuan}`
      );
    }

    console.log("Veritabanı başarıyla güncellendi.");
  } catch (err) {
    console.error("Veritabanı dosyası yazma hatası:", err);
  }
};

// Discord Functions
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

router.post("/post_leadboard", async (req, res) => {
  const { message } = req.body;
  // Gelen mesajı kontrol et
  if (!message) {
    return res.status(400).send("Mesaj boş olamaz.");
  }

  let obj;
  try {
    obj = JSON.parse(message);
  } catch (error) {
    console.error("Gelen mesaj JSON formatında değil:", error.message);
    return res.status(400).send("Geçersiz JSON formatı.");
  }
  //console.log(obj);
  // Gelen JSON'dan dosyayı indir
  const fileUrl = await getFileUrl(process.env.kullanici_puanlari); // İndirilecek dosyanın URL'sini alın
  const filePath = "data/geogame.json"; // Dosyanın kaydedileceği yerel yol
  try {
    await downloadFile(fileUrl, filePath);
    console.log("Dosya başarıyla indirildi: ", filePath);
  } catch (error) {
    return res.status(500).send("Dosya indirilemedi.");
  }
  try {
    await updateDatabase(obj);
  } catch (error) {
    console.error("Veritabanı güncellenemedi:", error.message);
    return res.status(500).send("Veritabanı güncellenemedi.");
  }
  const embed = {
    title: "🏆 Yeni Puan Logu",
    color: 0x2ecc71, // Yeşil renk
    fields: [
      { name: "👤 Oyuncu", value: `**İsim:** ${obj.name || "Bilinmiyor"}\n**UID:** \`${obj.uid || "Bilinmiyor"}\``, inline: false },
      { name: "🌍 Ülke", value: obj.ulke, inline: true },
      { name: "📊 Toplam Puan", value: obj.toplampuan, inline: true },
      { name: "📊 Sürümü", value: obj.surum, inline: true },
      { name: "Mesafe", value: `✅ Doğru: ${obj.mesafedogru}\n❌ Yanlış: ${obj.mesafeyanlis}\n📊 Puan: ${obj.mesafepuan}`, inline: true },
      { name: "Bayrak", value: `✅ Doğru: ${obj.bayrakdogru}\n❌ Yanlış: ${obj.bayrakyanlis}\n📊 Puan: ${obj.bayrakpuan}`, inline: true },
      { name: "Başkent", value: `✅ Doğru: ${obj.baskentdogru}\n❌ Yanlış: ${obj.baskentyanlis}\n📊 Puan: ${obj.baskentpuan}`, inline: true }
    ],
    thumbnail: {
      url: obj.profilurl // Kullanıcı profil fotoğrafı
    },
    footer: {
      text: "GeoGame Puan Tablosu",
      icon_url: "https://cdn.glitch.global/e74d89f5-045d-4ad2-94c7-e2c99ed95318/logo.png?v=1740170623412"
    },
    timestamp: new Date()
  };

  try {
    // Discord'a mesaj gönderme
    if (process.env.bot_token) {

      if (process.env.kullanici_puanlari) {
        sendFileToDiscord(filePath, process.env.kullanici_puanlari);
      } else {
        throw new Error("Kullanıcı puanları kanal ID'si eksik.");
      }

      // İkinci kanal (puan log kanalı)
      await sendMessageToDiscord("", process.env.puan_log, embed);
      
      return res
        .status(200)
        .send("Mesajlar ve dosya Discord'a başarıyla gönderildi!");
    } else {
      throw new Error("Bot tokeni eksik.");
    }
  } catch (error) {
    console.error("Veritabanı güncellenemedi: ", error.message);
    return res.status(500).send("Veritabanı güncellenemedi.");
  }
});
router.get("/get_leadboard", async (req, res) => {
  try {
    // getMessages() fonksiyonuyla dönen URL'yi alıyoruz
    const fileUrl = await getFileUrl(process.env.kullanici_puanlari);
    const filePath = "./user.json"; // İndirilecek dosyanın yerel yolu

    // Dosyayı indir
    await downloadFile(fileUrl, filePath);

    // Dosya indirildikten sonra, kullanıcıya dosyayı gönder
    res.download(filePath, "downloaded_file.json", (err) => {
      if (err) {
        console.error("Dosya gönderilirken hata oluştu:", err);
        res.status(500).send("Dosya gönderilemedi.");
      }
      // İndirilen dosyayı sil
      fs.unlink(filePath, (unlinkErr) => {
        if (unlinkErr) {
          console.error("Dosya silinirken hata oluştu:", unlinkErr);
        }
      });
    });
  } catch (error) {
    console.error("Dosya indirilirken hata oluştu:", error);
    res.status(500).send("Dosya indirilirken hata oluştu.");
  }
});

router.post("/ulkelog", async (req, res) => {
  const { message } = req.body;

  if (!message) {
    return res.status(400).send("Mesaj boş olamaz.");
  }

  try {
    // JSON içeriğini ayrıştır
    const logData = JSON.parse(message);

    // **Embed Mesajı Tanımla**
    const embed = {
      title: "🌍 Yeni Ülke Logu",
      color: 0x3498db, // Mavi renk
      fields: [
        { name: "👤 Oyuncu", value: `**İsim:** ${logData.name || "Bilinmiyor"}\n**UID:** \`${logData.uid || "Bilinmiyor"}\``, inline: false },
        { name: "🎮 Oyun Modu", value: logData.oyunmodu || "Bilinmiyor", inline: true },
        { name: "📝 Mesaj", value: `\`\`\`${logData.mesaj || "Mesaj yok"}\`\`\``, inline: false },
        { name: "✅ Doğru Cevap", value: logData.dogrucevap || "Belirtilmedi", inline: true },
        { name: "❌ Verilen Cevap", value: logData.verilencevap || "Boş", inline: true },
        { name: "🟢 Yeşil", value: logData.yesil || "Belirtilmedi", inline: true },
        { name: "🟡 Sarı", value: logData.sari || "Belirtilmedi", inline: true },
        { name: "🔵 Mavi", value: logData.mavi || "Belirtilmedi", inline: true },
        { name: "🔴 Kırmızı", value: logData.kirmizi || "Belirtilmedi", inline: true }
      ],
      footer: {
        text: "GeoGame Ülke Logu",
        icon_url: "https://cdn.glitch.global/e74d89f5-045d-4ad2-94c7-e2c99ed95318/logo.png?v=1740170623412"
      },
      timestamp: new Date()
    };

    // ✅ Embed mesajını gönder
    await sendMessageToDiscord(" ", process.env.secilen_ulke_log, embed);
    res.status(200).send("Log başarıyla gönderildi!");
  } catch (error) {
    console.error("Mesaj gönderilemedi:", error.response ? error.response.data : error.message);
    res.status(500).send("Mesaj gönderilirken bir hata oluştu.");
  }
});
router.post("/feedback", async (req, res) => {
  const { sebep, message, isim, uid } = req.body;

  if (!message) {
    return res.status(400).send("Mesaj boş olamaz.");
  }

  if (!isim || !uid) {
    return res.status(400).send("Kullanıcı bilgileri eksik.");
  }

  // **Embed Mesajı Tanımla**
  const embed = {
    title: "📩 Yeni Geri Bildirim",
    color: 0x2ecc71, // Yeşil renk
    fields: [
      { name: "🔎 Nedeni", value: sebep || "Belirtilmedi", inline: false },
      { name: "📧 Mesaj", value: "```" + message + "```", inline: false },
      { name: "👤 Kullanıcı", value: `**İsim:** ${isim}\n**UID:** \`${uid}\``, inline: false }
    ],
    footer: {
      text: "GeoGame Geri Bildirim",
      icon_url: "https://cdn.glitch.global/e74d89f5-045d-4ad2-94c7-e2c99ed95318/logo.png?v=1740170623412"
    },
    timestamp: new Date()
  };

  try {
    // ✅ Embed mesajını gönder
    await sendMessageToDiscord("<@&1329211479219634247>", process.env.feedback, embed);
    res.status(200).send("Mesaj başarıyla gönderildi!");
  } catch (error) {
    console.error("Mesaj gönderilemedi:", error.message);
    res.status(500).send("Mesaj gönderilirken bir hata oluştu.");
  }
});

router.post("/geogamesignlog", async (req, res) => {
  const { uid, name } = req.body;

  // Sebep ve name'in olup olmadığını kontrol et
  if (!name) {
    return res.status(400).send("isim boş olamaz.");
  }

  // **Embed Mesajı Tanımla**
  const embed = {
    title: "🚪 Kullanıcı Çıkış Yaptı",
    color: 0xe74c3c, // Kırmızı renk
    fields: [
       { name: "👤 Oyuncu", value: `**İsim:** ${name || "Bilinmiyor"}\n**UID:** \`${uid|| "Bilinmiyor"}\``, inline: false },
    ],
    footer: {
      text: "GeoGame Çıkış Logu",
      icon_url: "https://cdn.glitch.global/e74d89f5-045d-4ad2-94c7-e2c99ed95318/logo.png?v=1740170623412"
    },
    timestamp: new Date()
  };

  try {
    // ✅ Embed mesajını gönder
    await sendMessageToDiscord(" ", process.env.signlog, embed);
  } catch (error) {
    console.error("Mesaj gönderilemedi:", error.response ? error.response.data : error.message);
  }

  // Başarılı bir yanıt gönder
  res.status(200).send("Çıkış işlemi başarıyla kaydedildi.");
});
router.post('/login/callback', async (req, res) => {
    const userData = req.body;
    console.log('Received User Data:', userData);

    // **Embed mesajı tanımla**
    const embed = {
        title: "✅ Yeni Giriş Yapıldı!",
        color: 0x3498db, // Mavi renk
        fields: [
            { name: "👤 Oyuncu", value: `**İsim:** ${userData.displayName || "Bilinmiyor"}\n**UID:** \`${userData.uid|| "Bilinmiyor"}\``, inline: false },
        ],
        thumbnail: { url: userData.profilePicture }, // Profil resmi
        footer: { text: "Giriş Bildirimi", icon_url: "https://cdn.glitch.global/e74d89f5-045d-4ad2-94c7-e2c99ed95318/logo.png?v=1740170623412" },
        timestamp: new Date()
    };

    try {
        // ✅ Embed'i fonksiyona geçirerek mesaj gönder
        await sendMessageToDiscord(" ", process.env.signlog, embed);

        // Başarılı yanıt gönder
        res.json({
            uid: userData.uid,
            displayName: userData.displayName,
            profilePicture: userData.profilePicture
        });
    } catch (error) {
        console.error('Discord mesajı gönderilemedi:', error);
        res.status(500).json({ error: 'Mesaj gönderilemedi' });
    }
});

module.exports = router;