"""
Q-Ledger Forensic Analysis Functions & Visualizations
Provides statistical calculations, forensic anomaly checkpoints, and interactive charts.
"""

import pandas as pd
import plotly.express as px

# SAP Material type master mapping
material_type_data = {
    "Material Type": [
        "ABF",
        "CBAU",
        "CH00",
        "CONT",
        "COUP",
        "DIEN",
        "EPA",
        "ERSA",
        "FCKD",
        "FERT",
        "FFFC",
        "FGTR",
        "FHMI",
        "FOOD",
        "FRIP",
        "GBRA",
        "HALB",
        "HALF",
        "HAWA",
        "HERB",
        "HERS",
        "HIBE",
        "IBAU",
        "INTR",
        "KMAT",
        "LEER",
        "LEIH",
        "LGUT",
        "MCFE",
        "MCHA",
        "MCHF",
        "MCRO",
        "MODE",
        "MPO",
        "MRM1",
        "MRM3",
        "MRO1",
        "NLAG",
        "NOF1",
        "PART",
        "PHNT",
        "PIPE",
        "PLAN",
        "PMAT",
        "PROC",
        "PROD",
        "ROH",
        "ROH1",
        "ROH2",
        "ROH3",
        "ROH9",
        "SCRP",
        "SCRZ",
        "UNBW",
        "UNPA",
        "UPGV",
        "VBRA",
        "VEHI",
        "VERP",
        "VKHM",
        "VOLL",
        "VVGR",
        "WERB",
        "WERT",
        "WETT",
        "Not Applicable",
    ],
    "Material Type Description": [
        "Waste",
        "Compatible Unit",
        "CH Contract Handling",
        "Kanban Container",
        "Coupons",
        "Service",
        "Equipment Package",
        "PM Material",
        "Irregular CKD (FSC)",
        "Finished Product(FSC)",
        "Form-Fit-Function class",
        "Beverages",
        "Production Resource/Tool",
        "Foods (excl. perishables)",
        "Perishables",
        "ETM usable material",
        "Semifinished Product",
        "FSC(Body/Paint)",
        "Trading Goods",
        "Interchangeable part",
        "Manufacturer Part",
        "Consum. Mat.(Only Stock)",
        "Maintenance assemblies",
        "Intra materials",
        "Configurable materials",
        "Empties",
        "Returnable packaging",
        "Empties (retail)",
        "Mill Cable Finished Prdts",
        "Mill Cable Trading Goods",
        "MillCab.Semifinishd Prodt",
        "Mill Cable Raw Material",
        "Apparel (seasonal)",
        "Material Planning Object",
        "Mill Reel",
        "Mill Returnable Reel",
        "Mill Reel Without t. Data",
        "Consum.Material(NonStock)",
        "Nonfoods",
        "Part",
        "PHANTOM",
        "Pipeline materials",
        "Trading goods (planned)",
        "Plan Material for Vehicle",
        "Process materials",
        "Product groups",
        "Raw materials",
        "Raw materials (Coil)",
        "Sub-material",
        "Casting Material",
        "Costing Sub-material",
        "Scrap",
        "Other Scrap Material",
        "Nonvaluated materials",
        "sequenced trolley",
        "UPGVC",
        "ETM consumption material",
        "Vehicle config.",
        "Packaging",
        "Additionals",
        "Full products",
        "Competitor Product",
        "Product catalogs",
        "Value-only materials",
        "Competitor products",
        "Not Applicable",
    ],
}


def indian_rupee_format(amount) -> str:
    """Converts numeric amount into readable Indian Crore/Lakh currency representation."""
    try:
        val = float(amount)
        if abs(val) >= 10000000:
            return f"₹ {val / 10000000:.2f} Cr"
        elif abs(val) >= 100000:
            return f"₹ {val / 100000:.2f} L"
        else:
            return f"₹ {int(val):,}"
    except (ValueError, TypeError):
        return "₹ 0"


def convert_to_indian_format(value) -> str:
    """Formats numeric value with Indian digit grouping (without currency symbol)."""
    try:
        val = float(str(value).replace(",", ""))
        return f"{int(val):,}"
    except (ValueError, TypeError):
        return str(value)


def mater_list(filtered_df: pd.DataFrame, top_material_lc_df: pd.DataFrame) -> pd.DataFrame:
    """Formats material dataset for master inventory audit."""
    df = top_material_lc_df.copy()
    if "Pstng Date" in df.columns:
        df["Pstng Date"] = pd.to_datetime(df["Pstng Date"], errors="coerce").dt.date
    if "PO Date" in df.columns:
        df["PO Date"] = pd.to_datetime(df["PO Date"], errors="coerce").dt.date
    if "PO Qty" in df.columns and "GR Qty" in df.columns:
        df["PO Rem"] = df["PO Qty"] - df["GR Qty"]
    else:
        df["PO Rem"] = 0

    df = df.rename(
        columns={
            "Material Type Description": "Mat. Type Desc.",
            "PO Currency": "PO Curr.",
        }
    )

    mat_order = [
        "S/Loc",
        "Vendor Code & Name",
        "Creater",
        "Material",
        "Material Type.",
        "Description",
        "Spec",
        "G/L acct.",
        "Cost Ctr.",
        "PO Date",
        "Purchase order",
        "PO Curr.",
        "Net price",
        "PO Qty",
        "Pstng Date",
        "GR Qty",
        "PO Rem",
        "Amount LC",
    ]
    available_cols = [c for c in mat_order if c in df.columns]
    res = df[available_cols].copy()
    if "Amount LC" in res.columns:
        res["Amount LC"] = res["Amount LC"].fillna(0).astype(int)
    return res


def ersa(ersa_df: pd.DataFrame, df2: pd.DataFrame) -> pd.DataFrame:
    """Identifies ERSA (Spare Parts) booked against 4xxxx Operating Expense G/L accounts."""
    df = ersa_df.copy()
    df["G/L acct"] = df["G/L acct"].astype(str)
    df["Creater"] = df["Creater"].astype(str)

    # Filter G/L accounts starting with 4 (Expense / Spares)
    df = df[df["G/L acct"].str.startswith("4")]

    if "Material Type" in df.columns:
        final_result = df[df["Material Type"] == "ERSA"].copy()
    else:
        final_result = df.copy()

    if "PO Date" in final_result.columns:
        final_result["PO Date"] = pd.to_datetime(final_result["PO Date"], errors="coerce").dt.date

    final_result = final_result.drop_duplicates()
    columns = [
        "S/Loc",
        "Vendor Code & Name",
        "Creater",
        "Material Type.",
        "Material",
        "Description",
        "Spec",
        "G/L acct.",
        "Cost Ctr.",
        "Purchase order",
        "Net price",
    ]
    available = [c for c in columns if c in final_result.columns]
    return final_result[available]


def indir_mat(indir_mat_df: pd.DataFrame) -> pd.DataFrame:
    """Filters indirect materials (HIBE/ERSA) with stagnant unit prices over 2+ years."""
    df = indir_mat_df.copy()
    df["PO Date"] = pd.to_datetime(df["PO Date"], errors="coerce")
    df = df.dropna(subset=["PO Date"])

    grouped = (
        df.groupby(["Vendor", "Material", "Net price"])
        .agg({"PO Date": ["min", "max"]})
        .reset_index()
    )
    grouped.columns = ["Vendor", "Material", "Net price", "min_PO_Date", "max_PO_Date"]
    grouped["duration_days"] = (grouped["max_PO_Date"] - grouped["min_PO_Date"]).dt.days

    # Identify items spanning more than 730 days (2 years)
    filtered = grouped[grouped["duration_days"].abs() > 730].copy()
    if filtered.empty:
        return pd.DataFrame()

    merged = pd.merge(
        filtered,
        df,
        on=["Vendor", "Material", "Net price"],
        how="inner",
    ).drop_duplicates()

    if "Material Type" in merged.columns:
        merged = merged[merged["Material Type"].isin(["HIBE", "ERSA"])]

    merged["min_PO_Date"] = pd.to_datetime(merged["min_PO_Date"], errors="coerce").dt.date
    merged["max_PO_Date"] = pd.to_datetime(merged["max_PO_Date"], errors="coerce").dt.date

    cols = [
        "Cost Ctr.",
        "Vendor Code & Name",
        "Material",
        "Material Type.",
        "Description",
        "Spec",
        "G/L acct.",
        "PO Currency",
        "Net price",
        "min_PO_Date",
        "max_PO_Date",
        "duration_days",
    ]
    available = [c for c in cols if c in merged.columns]
    res = merged[available].rename(
        columns={"PO Currency": "PO Curr.", "duration_days": "Date_Diff"}
    )
    return res.drop_duplicates()


def group_by_words(word_df: pd.DataFrame) -> pd.DataFrame:
    """Groups items with identical token bags in their descriptions."""
    word_dict = {}
    for _, row in word_df.iterrows():
        desc = str(row.get("Description", ""))
        words = tuple(sorted(set(desc.split())))
        if words not in word_dict:
            word_dict[words] = []
        word_dict[words].append(row)
    result = []
    for word_set in word_dict.values():
        if len(word_set) > 1:
            result.extend(word_set)
    return pd.DataFrame(result) if result else word_df.head(0)


def dif_mat3(dif_mat_df: pd.DataFrame, df2: pd.DataFrame):
    """Detects materials having the same description but categorized under conflicting Material Types."""
    df = dif_mat_df.copy()
    cols = ["Cost Ctr.", "Vendor Code & Name", "Material", "Material Type.", "Description", "Spec"]
    available = [c for c in cols if c in df.columns]
    selected = df[available].drop_duplicates(subset=["Spec", "Material"])
    selected = selected.sort_values(by=["Description", "Material"])

    result = group_by_words(selected).drop_duplicates()
    return df, df2, result


def openpo(openpo_df: pd.DataFrame) -> pd.DataFrame:
    """Identifies aging open purchase orders (>750 days) with pending delivery quantities."""
    df = openpo_df.copy()
    df["PO Date"] = pd.to_datetime(df["PO Date"], errors="coerce")
    df = df.dropna(subset=["PO Date"])
    today = pd.Timestamp.now().normalize()

    grouped = df.groupby(
        ["Purchase order", "G/L acct.", "Material", "Description", "PO Qty", "PO Currency"],
        as_index=False,
    ).agg(
        {
            "Material Type.": "first",
            "Spec": "first",
            "GR Qty": "sum",
            "PO Date": "min",
            "Net price": "first",
        }
    )

    grouped["Date_Diff"] = (today - grouped["PO Date"]).dt.days
    grouped["GR Qty"] = grouped["GR Qty"].round(2)
    grouped["PO Rem."] = (grouped["PO Qty"] - grouped["GR Qty"]).round(5)
    grouped = grouped[grouped["PO Rem."] > 0]
    grouped = grouped[grouped["Date_Diff"] > 750]

    if grouped.empty:
        return pd.DataFrame()

    grouped["PO Rem Value"] = (grouped["PO Rem."] * grouped["Net price"]).apply(
        convert_to_indian_format
    )
    grouped["PO Date"] = grouped["PO Date"].dt.date
    grouped["Today Date"] = today.date()

    new_order = [
        "Purchase order",
        "Material",
        "Material Type.",
        "Description",
        "Spec",
        "G/L acct.",
        "PO Date",
        "Today Date",
        "PO Qty",
        "GR Qty",
        "PO Rem.",
        "PO Currency",
        "Net price",
        "PO Rem Value",
        "Date_Diff",
    ]
    available = [c for c in new_order if c in grouped.columns]
    res = grouped[available].rename(columns={"PO Currency": "Net Price Curr."})
    return res.drop_duplicates()


def tab66(tab66_df: pd.DataFrame):
    """Flags purchase orders where Goods Receipt delivery intervals exceed 365 days."""
    df = tab66_df.copy()
    required = ["Material", "Purchase order", "Pstng Date", "PO Qty", "GR Qty"]
    if not all(col in df.columns for col in required):
        return pd.DataFrame(), pd.DataFrame()

    df = df.sort_values(by=["Material", "Purchase order", "Pstng Date"])
    df["Pstng Date"] = pd.to_datetime(df["Pstng Date"], errors="coerce")
    df = df.dropna(subset=["Pstng Date"])

    df["Date_Diff"] = df.groupby(["Material", "Purchase order"])["Pstng Date"].diff().dt.days
    df = df.reset_index(drop=True)

    filtered_rows = df[df["Date_Diff"] > 365].copy()
    if filtered_rows.empty:
        return pd.DataFrame(), pd.DataFrame()

    indices = filtered_rows.index
    valid_prev_indices = [i - 1 for i in indices if i > 0]
    previous_rows = df.loc[valid_prev_indices].copy()

    filtered_rows["Type"] = "Filtered"
    previous_rows["Type"] = "Previous"

    combined = pd.concat([filtered_rows, previous_rows]).sort_index()
    combined["Pstng Date"] = combined["Pstng Date"].dt.date
    if "PO Qty" in combined.columns and "GR Qty" in combined.columns:
        combined["PO Rem."] = (combined["PO Qty"] - combined["GR Qty"]).round(5)

    cols = [
        "Cost Ctr.",
        "Purchase order",
        "Vendor Code & Name",
        "Material",
        "Description",
        "Spec",
        "G/L acct.",
        "Pstng Date",
        "Date_Diff",
        "PO Qty",
        "GR Qty",
        "Type",
    ]
    available = [c for c in cols if c in combined.columns]
    return combined[available].drop_duplicates(), filtered_rows


def process_data_t7(tab7_df: pd.DataFrame):
    """Detects Goods Receipts posted more than 365 days after PO Creation Date."""
    df = tab7_df.copy()
    required = ["Material", "Purchase order", "Pstng Date", "PO Date"]
    if not all(col in df.columns for col in required):
        return None, f"Required columns missing: {', '.join(required)}"

    df["PO Date"] = pd.to_datetime(df["PO Date"], errors="coerce")
    df["Pstng Date"] = pd.to_datetime(df["Pstng Date"], errors="coerce")
    df = df.dropna(subset=["PO Date", "Pstng Date"])

    df["Date_Diff"] = (df["Pstng Date"] - df["PO Date"]).dt.days
    delayed = df[df["Date_Diff"] > 365].copy()
    if delayed.empty:
        return pd.DataFrame(), None

    delayed["PO Date"] = delayed["PO Date"].dt.date
    delayed["Pstng Date"] = delayed["Pstng Date"].dt.date

    cols = [
        "Cost Ctr.",
        "Purchase order",
        "G/L acct.",
        "Vendor Code & Name",
        "Material",
        "Description",
        "Spec",
        "PO Date",
        "Pstng Date",
        "Date_Diff",
        "PO Qty",
        "GR Qty",
    ]
    available = [c for c in cols if c in delayed.columns]
    return delayed[available].drop_duplicates(), None


# ==========================================
# ForensiQ Dynamic Plotly Chart Engines
# ==========================================

PLOTLY_THEME_LAYOUT = {
    "paper_bgcolor": "rgba(0,0,0,0)",
    "plot_bgcolor": "rgba(0,0,0,0)",
    "font": {"family": "Inter, sans-serif", "color": "#a1a1aa"},
    "margin": {"l": 20, "r": 20, "t": 40, "b": 20},
}


def row2_c1(top_gl_df: pd.DataFrame, filtered_df: pd.DataFrame):
    """Top 10 Vendors by Year spend distribution."""
    df = filtered_df.copy()
    df["Year"] = pd.to_datetime(df["PO Date"], errors="coerce").dt.year.fillna(0).astype(int)

    pivot = df.groupby(["Vendor", "Year"])["Amount LC"].sum().unstack(fill_value=0)
    pivot["Total"] = pivot.sum(axis=1)
    top10 = (
        pivot.sort_values("Total", ascending=False).head(10).drop(columns=["Total"]).reset_index()
    )

    melted = top10.melt(id_vars="Vendor", var_name="Year", value_name="Spend")
    melted["Formatted"] = melted["Spend"].apply(indian_rupee_format)

    fig = px.bar(
        melted,
        x="Vendor",
        y="Spend",
        color="Year",
        barmode="group",
        height=380,
        custom_data=["Formatted"],
        color_discrete_sequence=["#f59e0b", "#3b82f6", "#10b981", "#8b5cf6", "#ec4899"],
    )
    fig.update_traces(
        hovertemplate="Vendor: %{x}<br>Spend: %{customdata[0]}<extra>%{data.name}</extra>",
    )
    fig.update_layout(
        **PLOTLY_THEME_LAYOUT,
        yaxis_title="Spend in INR",
        legend_title="Year",
        hovermode="closest",
    )
    return fig


def row2_c2(filtered_df: pd.DataFrame):
    """Spend breakdown across Cost Centers (in Lakhs)."""
    df = filtered_df.copy()
    grouped = df.groupby("Cost Ctr")["Amount LC"].sum().reset_index()
    grouped["Formatted"] = grouped["Amount LC"].apply(indian_rupee_format)
    grouped["Amount LC"] = (grouped["Amount LC"] / 100000).round(2)
    grouped = grouped.sort_values(by="Amount LC", ascending=False).head(12)

    fig = px.bar(
        grouped,
        x="Cost Ctr",
        y="Amount LC",
        color="Amount LC",
        color_continuous_scale="Viridis",
        height=380,
        custom_data=["Formatted"],
        labels={"Amount LC": "Amount (₹ Lakhs)", "Cost Ctr": "Cost Center"},
    )
    fig.update_traces(
        hovertemplate="Cost Center: %{x}<br>Amount: %{customdata[0]}<extra></extra>",
    )
    fig.update_layout(
        **PLOTLY_THEME_LAYOUT,
        showlegend=False,
        coloraxis_showscale=False,
    )
    return fig


def row2_c3(filtered_df: pd.DataFrame):
    """Cross-tabulation of Cost Centers & G/L Accounts (in Lakhs)."""
    df = filtered_df.copy()
    grouped = (
        df.groupby(["Cost Ctr", "G/L acct"])["Amount LC"].sum().unstack(fill_value=0).reset_index()
    )

    for col in grouped.columns[1:]:
        grouped[col] = (pd.to_numeric(grouped[col], errors="coerce") / 100000).round(2)

    top_cost_centers = grouped.head(8)
    gl_cols = list(top_cost_centers.columns[1:])

    melted = top_cost_centers.melt(
        id_vars="Cost Ctr", value_vars=gl_cols, var_name="G/L Account", value_name="Amount"
    )
    melted["Formatted"] = (melted["Amount"] * 100000).apply(indian_rupee_format)

    fig = px.bar(
        melted,
        x="Cost Ctr",
        y="Amount",
        color="G/L Account",
        barmode="group",
        height=380,
        custom_data=["Formatted"],
        color_discrete_sequence=["#f59e0b", "#8b5cf6", "#3b82f6", "#10b981", "#06b6d4"],
        labels={"Amount": "Amount (₹ Lakhs)", "Cost Ctr": "Cost Center"},
    )
    fig.update_traces(
        hovertemplate="Cost Center: %{x}<br>Amount: %{customdata[0]}<extra>%{data.name}</extra>",
    )
    fig.update_layout(
        **PLOTLY_THEME_LAYOUT,
        showlegend=False,
        coloraxis_showscale=False,
    )
    return grouped, fig
