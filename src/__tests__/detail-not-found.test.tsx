import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { RepositoryDetailContent } from "../routes/repository-detail";
import { ImageDetailContent } from "../routes/image-detail";

describe("detail pages not-found fallback", () => {
  test("repository detail renders explicit not-found card when no data and no error", () => {
    const html = renderToStaticMarkup(
      <RepositoryDetailContent
        data={null}
        loading={false}
        error={null}
        retry={() => {}}
      />,
    );

    expect(html).toContain("Repository not found");
    expect(html).toContain("Back to Repositories");
  });

  test("image detail renders explicit not-found card when no data and no error", () => {
    const html = renderToStaticMarkup(
      <ImageDetailContent
        data={null}
        loading={false}
        error={null}
        retry={() => {}}
      />,
    );

    expect(html).toContain("Image not found");
    expect(html).toContain("Back to Images");
  });
});
