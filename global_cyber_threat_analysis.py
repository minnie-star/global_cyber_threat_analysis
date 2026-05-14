import pandas as pd
import matplotlib.pyplot as plt

# load and preprocess data
def load_data(filepath):
    df = pd.read_csv("final_kaggle_cyber_dataset.csv")
    df['reported_date'] = pd.to_datetime(df['reported_date'], errors='coerce')
    df = df.dropna(subset=['ip_address', 'country_name', 'abuse_confidence_score'])
    df['month'] = df['reported_date'].dt.to_period('M')
    return df

# analyze counts of suspicious IPs by country
def analyze_country_counts(df):
    return df['country_name'].value_counts()

# analyze average abuse confidence score by country
def analyze_avg_scores(df):
    return df.groupby('country_name')['abuse_confidence_score'].mean().sort_values(ascending=False)

# analyze trends over time
def analyze_monthly_trends(df):
    return df['month'].value_counts().sort_index()

# visualization functions
def plot_bar(data, title):
    plt.figure(figsize=(10,6))
    data.plot(kind='bar', title=title)
    plt.show()

def plot_line(data, title):
    plt.figure(figsize=(10,6))
    data.plot(kind='line', marker='o', title=title)
    plt.show()

if __name__ == "__main__":
    df = load_data("final_kaggle_cyber_dataset.csv")
    country_counts = analyze_country_counts(df)
    avg_scores = analyze_avg_scores(df)
    monthly_trends = analyze_monthly_trends(df)

    print(country_counts.head(10))
    print(avg_scores.head(10))
    print(monthly_trends)

    plot_bar(country_counts.head(10), "Top 10 Countries by Suspicious IPs")
    plot_bar(avg_scores.head(10), "Average Abuse Confidence Score per Country")
    plot_line(monthly_trends, "Monthly Malicious Activity Trends")
