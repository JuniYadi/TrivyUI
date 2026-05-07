import { describe, expect, test } from "bun:test";
import { paginateList } from "../utils/paginate-list";

describe("paginateList", () => {
  test("returns first 10 items by default", () => {
    const input = Array.from({ length: 25 }, (_, idx) => idx + 1);
    const result = paginateList(input);

    expect(result.items.length).toBe(10);
    expect(result.items[0]).toBe(1);
    expect(result.items[9]).toBe(10);
    expect(result.pagination.page).toBe(1);
    expect(result.pagination.limit).toBe(10);
    expect(result.pagination.total_items).toBe(25);
    expect(result.pagination.total_pages).toBe(3);
  });

  test("returns correct second page slice", () => {
    const input = Array.from({ length: 25 }, (_, idx) => idx + 1);
    const result = paginateList(input, 2, 10);

    expect(result.items.length).toBe(10);
    expect(result.items[0]).toBe(11);
    expect(result.items[9]).toBe(20);
    expect(result.pagination.page).toBe(2);
  });
});
