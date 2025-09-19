// "use server";

import { env } from "@/lib/env";
import { SubscriptionType, type TWebhookRequest } from "@/lib/shop/types";
import { Db } from "@/lib/supabase/server";
import type { Order } from "@/lib/supabase/table.types";
// import crypto from "node:crypto";

export const runtime = "edge";

type LemonEvent = {
  // 按你项目里接收的字段定义（示意）
  meta?: { event_name?: string };
  data?: unknown;
};

// 计算 HMAC-SHA256 (hex)
async function hmacSHA256Hex(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  // 转 hex
  const bytes = new Uint8Array(sig);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

// 常量时间对比（简易实现，避免时序泄露）
function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) {
    out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return out === 0;
}

export async function POST(request: Request) {
  // 1) 读取原始正文（字符串！不要先 JSON.parse）
  const rawBody = await request.text();

  // 2) 取 Lemon Squeezy 的签名头
  const signature = request.headers.get("X-Signature") || "";

  // 3) 用你的签名密钥重新计算 HMAC
  const secret = process.env.LEMON_SQUEEZY_WEBHOOK_SECRET || "";
  if (!secret) {
    return new Response("Missing signing secret", { status: 500 });
  }

  const expectSig = await hmacSHA256Hex(secret, rawBody);

  if (!timingSafeEqualHex(signature, expectSig)) {
    return new Response("Invalid signature", { status: 401 });
  }

  // 4) 验证通过再解析 JSON
  const event = JSON.parse(rawBody) as LemonEvent;

  // TODO: 根据事件类型执行业务逻辑
  // 例如：
  // if (event.meta?.event_name === "order_created") { ... }

  return new Response("ok", { status: 200 });
}


/* https://docs.lemonsqueezy.com/help/webhooks#events-sent-during-a-subscriptions-lifecycle
Initial order is placed:
1. subscription_created
2. subscription_payment_success
*/
async function handle(req: TWebhookRequest): Promise<{ error: string }> {
  const db = new Db();
  const { user_email, order_id, status, renews_at, ends_at, variant_id } = req.data.attributes;
  const order: Order = {
    // the same email address will represent a single user:
    // https://supabase.com/docs/guides/auth/auth-identity-linking#automatic-linking
    email: user_email,
    id: order_id,
    subscription_id: req.data.id,
    status,
    plan: "free",
    renews_at,
    ends_at,
    variant_id,
  };
  order.plan = getPlan(order);

  try {
    await db.upsertOrder(order);
  } catch (error: any) {
    console.error("DB access failed:", error, order);
    return { error: error.message };
  }

  return { error: "" };
}

function getPlan(order: Order): SubscriptionType {
  switch (order.status) {
    case "unpaid":
      return "free";
    case "expired":
      return "free";
  }

  for (const [t, id] of Object.entries(env.LEMONSQUEEZY_SUBSCRIPTION_VARIANT_MAP)) {
    if (order.variant_id === id) {
      return t as SubscriptionType;
    }
  }

  console.error(`Unknown variant_id: ${order.variant_id}`);
  return "free";
}
