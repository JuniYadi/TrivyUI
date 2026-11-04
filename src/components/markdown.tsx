import type { ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

type BunLike = {
  markdown?: {
    react?: (content: string, overrides?: unknown, options?: { reactVersion?: number }) => ReactNode;
  };
};

function renderMarkdownInRuntime(content: string, bunRuntime: BunLike | undefined) {
  if (bunRuntime?.markdown?.react) {
    return bunRuntime.markdown.react(content, undefined, { reactVersion: 18 });
  }

  return <ReactMarkdown remarkPlugins={[remarkGfm]} skipHtml>{content}</ReactMarkdown>;
}

function renderMarkdown(content: string) {
  const runtime = (globalThis as typeof globalThis & { Bun?: BunLike }).Bun;
  return renderMarkdownInRuntime(content, runtime);
}

export { renderMarkdown, renderMarkdownInRuntime };
