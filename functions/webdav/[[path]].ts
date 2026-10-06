import { notFound, parseBucketPath } from "./utils";
import { handleRequestCopy } from "./copy";
import { handleRequestDelete } from "./delete";
import { handleRequestGet } from "./get";
import { handleRequestHead } from "./head";
import { handleRequestMkcol } from "./mkcol";
import { handleRequestMove } from "./move";
import { handleRequestPropfind } from "./propfind";
import { handleRequestPut } from "./put";
import { RequestHandlerParams } from "./utils";
import { handleRequestPost } from "./post";

async function handleRequestOptions() {
  return new Response(null, {
    headers: {
      Allow: Object.keys(HANDLERS).join(", "),
      DAV: "1",
    },
  });
}

async function handleMethodNotAllowed() {
  return new Response(null, { status: 405 });
}

const HANDLERS: Record<
  string,
  (context: RequestHandlerParams) => Promise<Response>
> = {
  PROPFIND: handleRequestPropfind,
  MKCOL: handleRequestMkcol,
  HEAD: handleRequestHead,
  GET: handleRequestGet,
  POST: handleRequestPost,
  PUT: handleRequestPut,
  COPY: handleRequestCopy,
  MOVE: handleRequestMove,
  DELETE: handleRequestDelete,
};

export const onRequest: PagesFunction<{
  WEBDAV_USERNAME: string;
  WEBDAV_PASSWORD: string;
  WEBDAV_PUBLIC_READ?: string;
  PUBLIC_DIR?: string;
}> = async function (context) {
  const env = context.env;
  const request: Request = context.request;
  if (request.method === "OPTIONS") return handleRequestOptions();

  // 解析请求路径（用于判断是否命中公开目录）
  const pathSegments = ((context.params as any)?.path || []) as string[];
  const reqPath = decodeURIComponent(pathSegments.join("/"));

  // 公开目录：PUBLIC_DIR 下的文件允许免鉴权读取（GET/HEAD/PROPFIND）
  // 例如 PUBLIC_DIR=public，则 /webdav/public/xxx.mp4 可直接访问，其余路径照旧需要鉴权
  // 未配置 PUBLIC_DIR 时该机制关闭，不影响现有行为
  const publicDir = (env.PUBLIC_DIR || "").replace(/^\/+|\/+$/g, "");
  const isPublicPath =
    publicDir !== "" &&
    (reqPath === publicDir || reqPath.startsWith(publicDir + "/"));

  const skipAuth =
    ["GET", "HEAD", "PROPFIND"].includes(request.method) &&
    (env.WEBDAV_PUBLIC_READ === "1" || isPublicPath);

  if (!skipAuth) {
    if (!env.WEBDAV_USERNAME || !env.WEBDAV_PASSWORD)
      return new Response("WebDAV protocol is not enabled", { status: 403 });

    const auth = request.headers.get("Authorization");
    if (!auth) {
      return new Response("Unauthorized", {
        status: 401,
        headers: { "WWW-Authenticate": `Basic realm="WebDAV"` },
      });
    }
    const expectedAuth = `Basic ${btoa(
      `${env.WEBDAV_USERNAME}:${env.WEBDAV_PASSWORD}`
    )}`;
    if (auth !== expectedAuth)
      return new Response("Unauthorized", { status: 401 });
  }

  const [bucket, path] = parseBucketPath(context);
  if (!bucket) return notFound();

  const method: string = (context.request as Request).method;
  const handler = HANDLERS[method] ?? handleMethodNotAllowed;
  return handler({ bucket, path, request: context.request });
};

