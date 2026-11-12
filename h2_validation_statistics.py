import csv
import math

FILE = "h2_validation_results.csv"

COMPARISONS = [
    ("A_URL_DOMAIN", "D_FULL"),
    ("B_BRAND_LEXICAL", "D_FULL"),
    ("C_TLS", "D_FULL"),
]


def exact_mcnemar_p(b, c):
    """
    Exact two-sided McNemar test using the binomial distribution.

    b = first configuration correct, second incorrect
    c = first configuration incorrect, second correct
    """
    n = b + c

    if n == 0:
        return 1.0

    k = min(b, c)

    probability = sum(
        math.comb(n, i) * (0.5 ** n)
        for i in range(k + 1)
    )

    return min(1.0, 2 * probability)


with open(FILE, newline="", encoding="utf-8-sig") as f:
    rows = list(csv.DictReader(f))


print("=" * 72)
print("PHISHGUARD H2 VALIDATION PAIRED STATISTICAL ANALYSIS")
print("=" * 72)
print(f"Observations: {len(rows)}")
print("Test: Exact two-sided McNemar")
print("Alpha: 0.05")
print()


for first, second in COMPARISONS:

    both_correct = 0
    first_only_correct = 0
    second_only_correct = 0
    both_incorrect = 0

    for row in rows:

        truth = row["ground_truth"]

        first_correct = (
            row[f"{first}_prediction"] == truth
        )

        second_correct = (
            row[f"{second}_prediction"] == truth
        )

        if first_correct and second_correct:
            both_correct += 1

        elif first_correct and not second_correct:
            first_only_correct += 1

        elif not first_correct and second_correct:
            second_only_correct += 1

        else:
            both_incorrect += 1

    p = exact_mcnemar_p(
        first_only_correct,
        second_only_correct
    )

    print("-" * 72)
    print(f"{first} vs {second}")
    print("-" * 72)

    print(f"Both correct:              {both_correct}")
    print(f"{first} only correct: {first_only_correct}")
    print(f"{second} only correct:       {second_only_correct}")
    print(f"Both incorrect:            {both_incorrect}")
    print(
        "Discordant pairs:          "
        f"{first_only_correct + second_only_correct}"
    )

    print(f"Exact McNemar p-value:     {p:.8f}")

    if p < 0.05:
        print("Statistically significant at alpha = 0.05")
    else:
        print("Not statistically significant at alpha = 0.05")

    print()


print("=" * 72)
print("ANALYSIS COMPLETE")
print("=" * 72)
