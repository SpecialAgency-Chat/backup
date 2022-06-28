// https://is.gd/fDnFdR

import dotenv from "dotenv"
dotenv.config();

import { Client, Permissions, Snowflake, CommandInteraction, MessageActionRow, MessageButton, Guild, User } from "discord.js";
import axios from "axios";
import mongoose from "mongoose";
import cron from "node-cron";
import express from "express";
import sjcl, { SjclCipherDecrypted } from "sjcl";
import { APIUser, RESTPostOAuth2AccessTokenResult, RESTPostOAuth2RefreshTokenResult } from "discord-api-types/v9";
import { setTimeout as sleep } from "timers/promises";

if (!process.env.CLIENT_SECRET) throw new Error("no client secret");

const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.NODE_ENV === "development" ? "http://localhost:8080/oauth2/callback":"本番用";

if (!process.env.MONGO_URL) throw new Error("no mongo url");
mongoose.connect(process.env.MONGO_URL);

if (!process.env.BOT_TOKEN) throw new Error("no bot token");

if (!process.env.ENCRYPT_KEY) throw new Error("no encrypt key");
const encryptKey = process.env.ENCRYPT_KEY;

type UserData = {
  id: Snowflake,
  accessToken: string,
  refreshToken: string,
  refreshedAt: Date,
  save(): Promise<void>
} | null;

const userSchema = new mongoose.Schema({
  id: String,
  accessToken: String,
  refreshToken: String,
  refreshedAt: Date
});
const userDb = mongoose.model("user", userSchema);

const { FLAGS } = Permissions;
type FLAGTYPE = keyof typeof FLAGS;
type PermissionOverwrite = {
  name: string,
  allow: FLAGTYPE[],
  deny: FLAGTYPE[],
  id: string
}

type Text = {
  name: string,
  topic: string,
  permissionOverwrites: PermissionOverwrite[],
  position: number,
  slowmode: number,
  news: boolean
};

type Voice = {
  name: string,
  permissionOverwrites: PermissionOverwrite[],
  position: number
}

type Category = {
  name: string,
  position: number,
  children: (Text | Voice)[]
}

type Role = {
  name: string,
  position: string,
  color: number,
  hoist: boolean,
  mentionable: boolean,
  permissions: FLAGTYPE[]
}

type PartialExclude<T extends object, K extends keyof T> = { [P in Exclude<keyof T, K>]?: T[P] } & { [P in K]-?: T[P] };

type GuildData = PartialExclude<{
  id: string,
  role: string,
  subServer: string[],
  ownerToken: string,
  channels: (Category | Text | Voice)[],
  roles: Role[],
  users: Snowflake[],
  save(): Promise<void>
}, "save"> | null;

const guildSchema = new mongoose.Schema({
  id: String,
  role: String,
  subServer: Array,
  ownerToken: String,
  /**
   * @type {(Category | Text | Voice)[]}
   */
  channels: Array,
  /**
   * @type {Role[]}
   */
  roles: Array,
  /**
   * @type {string[]}
   */
  users: Array,
  memberCount: Number
});

const guildDb = mongoose.model("guild", guildSchema)
const app = express();
const client = new Client({ intents: 32767 });

// bot

client.on("ready", (cl) => {
  console.log("ready");
  cl.application.commands.set([
    {
      name: "auth",
      description: "認証パネルを設置",
      options: [
        {
          type: "STRING",
          name: "title",
          description: "title"
        },
        {
          type: "STRING",
          name: "description",
          description: "description"
        },
        {
          type: "ATTACHMENT",
          name: "image",
          description: "image"
        }
      ]
    },
    {
      name: "role",
      description: "認証後ロールを設定",
      options: [{
        type: "ROLE",
        name: "role",
        description: "role",
        required: true
      }]
    },
    {
      name: "backup-manual",
      description: "サーバーをバックアップ(手動)"
    },
    {
      name: "restore",
      description: "みんな戻ってこーい！",
      options: [
        {
          name: "action",
          description: "どうする？",
          required: true,
          type: "STRING",
          choices: [
            {
              name: "チャンネル/ロールのみ",
              value: "channel/role"
            },
            {
              name: "ユーザーのみ",
              value: "user"
            },
            {
              name: "全部",
              value: "all"
            }
          ]
        },
        {
          type: "ROLE",
          name: "role",
          description: "戻した時に全員にロールを付与する",
        }
      ]
    }
  ])
});

const checkAdmin = async (i: CommandInteraction<"cached">): Promise<boolean> => {
  if (!i.member.permissions.has(FLAGS.ADMINISTRATOR)) {
    await i.reply({ content: "管理者権限を保有していないユーザーが実行することはできません。", ephemeral: true });
    return false;
  }
  return true;
}

cron.schedule("0 0 0 */3 * *", async () => {
  const users: NonNullable<UserData>[] = await userDb.find();
  for (const user of users) {
    const params = new URLSearchParams();
    params.append("grant_type", "refresh_token");
    params.append("refresh_token", user.refreshToken);
    params.append("client_id", client.user!.id);
    params.append("client_secret", CLIENT_SECRET);
    try {
      const res = await axios.post<RESTPostOAuth2RefreshTokenResult>("https://discordapp.com/api/oauth2/token", params, {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        }
      });
      userDb.findOneAndUpdate({ id: user.id }, { $set: { accessToken: res.data.access_token, refreshedAt: new Date() } }, { new: true }).exec();
    } catch {
      await userDb.deleteOne({ id: user.id });
    }
    await sleep(2000);
  }
})

client.on("interactionCreate", async (i) => {
  if (!i.inCachedGuild()) {
    return;
  }
  if (i.isCommand()) {
    const { commandName: command } = i;
    if (command === "auth") {
      if (!await checkAdmin(i)) return;
      await i.deferReply({ ephemeral: true });
      const data: GuildData = await guildDb.findOne({ id: i.guildId });
      if (!data || !data.role) {
        i.followUp("ロールがまだ設定されていません。`/role`コマンドで設定してください。");
        return;
      }
      const but = new MessageButton()
        .setStyle("LINK")
        .setURL(`https://discord.com/oauth2/authorize?client_id=${client.user?.id}&redirect_uri=${(REDIRECT_URI)}&response_type=code&scope=${encodeURIComponent("identify guilds.join")}&state=${Buffer.from(
          sjcl.encrypt(encryptKey, `${i.guildId}`) as unknown as string
        ).toString("base64")}`)
        .setLabel("認証ページに行く");
      i.channel?.send({
        embeds: [
          {
            title: i.options.getString("title") || "認証",
            description: i.options.getString("description") || "下のボタンを押して認証してください",
            image: i.options.getAttachment("image")?.url ? { url: i.options.getAttachment("image")?.url } : void 0,
          }
        ],
        components: [new MessageActionRow().addComponents(but)]
      });
      i.followUp("設置しました。");
    } else if (command === "role") {
      if (!await checkAdmin(i)) return;
      await i.deferReply({ ephemeral: true });
      const role = i.options.getRole("role");
      if (!role) {
        i.followUp("ロールが指定されていません。");
        return;
      }
      if (role.managed) {
        i.followUp("このロールは連携によって設定されています。");
        return;
      }
      const data: NonNullable<GuildData> = await guildDb.findOne({ id: i.guildId }) || new guildDb({ id: i.guildId });
      data.role = role.id;
      await data.save();
      i.followUp("設定しました。");
      console.log(await guildDb.findOne({ id: i.guildId }));
    }
  }
});

app.all("/oauth2/callback", async (req, res) => {
  const code = req.query.code as string | undefined;
  if (!code) {
    res.status(400).send("codeが指定されていません。");
    return;
  }
  const rawState = req.query.state;
  if (!rawState) {
    res.status(400).send("stateが指定されていません。");
    return;
  }
  try {
    const state = sjcl.decrypt(encryptKey, Buffer.from(rawState as string, "base64").toString("utf8"));
    const guildId = state.split("|")[0];
    const guildData: GuildData = await guildDb.findOne({ id: guildId });
    if (!guildData) {
      res.status(400).send("guildDataが見つかりません。");
      return;
    }
    const params = new URLSearchParams();
    params.append("client_id", client.user!.id);
    params.append("client_secret", CLIENT_SECRET);
    params.append("grant_type", "authorization_code");
    params.append("code", code);
    params.append("redirect_uri", REDIRECT_URI);
    const { data } = await axios.post<RESTPostOAuth2AccessTokenResult>(`https://discordapp.com/api/oauth2/token`, params, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      validateStatus: () => true
    });
    if (!data.access_token) {
      res.status(400).send("access_tokenが取得できませんでした。");
      return;
    }
    if (!data.scope.includes("identify") || !data.scope.includes("guilds.join")) {
      res.status(400).send("scopeが不正です。");
      return;
    }
    console.log(data);
    const { data: userData } = await axios.get<APIUser>(`https://discordapp.com/api/users/@me`, {
      headers: {
        Authorization: `Bearer ${data.access_token}`
      },
      validateStatus: () => true
    });
    const data2: NonNullable<UserData> = new userDb<Omit<NonNullable<UserData>, "save">>({ id: userData.id, accessToken: data.access_token, refreshToken: data.refresh_token, refreshedAt: new Date() });
    await data2.save();
    const guild = client.guilds.cache.get(guildId);
    if (guild) {
      const member = guild.members.cache.get(userData.id);
      if (member) {
        const role = guild.roles.cache.get(guildData.role!);
        if (role) {
          await member.roles.add(role);
        }
      }
    }
    "a".toUpperCase()
    res.status(200).send("ok");
  } catch (e) {
    console.log(e);
    res.status(400).send("stateが不正です。");
    return;
  }
});

client.login(process.env.BOT_TOKEN);
app.listen(process.env.PORT || 8080);