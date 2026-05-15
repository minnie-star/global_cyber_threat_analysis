import pandas as pd
import matplotlib.pyplot as plt
import os

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

# Find the most frequently reported suspicious IP addresses
def analyze_top_ip_addresses(df, n=10):
    return df['ip_address'].value_counts().head(n)

# Aggregate suspicious IP counts by continent
def analyze_by_continent(df):
    return df['continent'].value_counts()

#Show attack distribution by time zone or reported hour
def analyze_time_of_day(df):
    return df['time_zone_attack'].value_counts()

# Summarize counts of different risk levels
def analyze_risk_levels(df):
    return df['risk_level'].value_counts()

# Show which weekdays have the highest reported activity
def analyze_weekday_trends(df):
    return df['reported_weekday'].value_counts().sort_index()


# visualization functions to plot and display results 
# def plot_bar(data, title):
#     plt.figure(figsize=(10,6))
#     data.plot(kind='bar', title=title)
#     plt.show()

# def plot_line(data, title):
#     plt.figure(figsize=(10,6))
#     data.plot(kind='line', marker='o', title=title)
#     plt.show()

# visualization functions to plot and display results with saving to files
# Updated to save plots to "results" directory instead of showing them directly
def plot_bar(data, title, filename):
    plt.figure(figsize=(10,6))
    data.plot(kind='bar', title=title)
    plt.tight_layout()
    os.makedirs("results", exist_ok=True)  
    plt.savefig(f"results/{filename}.png")
    plt.close()

def plot_line(data, title, filename):
    plt.figure(figsize=(10,6))
    data.plot(kind='line', marker='o', title=title)
    plt.tight_layout()
    os.makedirs("results", exist_ok=True)
    plt.savefig(f"results/{filename}.png")
    plt.close()

# main execution block to run analyses and generate visualizations
if __name__ == "__main__":
    df = load_data("final_kaggle_cyber_dataset.csv")
    country_counts = analyze_country_counts(df)
    avg_scores = analyze_avg_scores(df)
    monthly_trends = analyze_monthly_trends(df)

    top_ips = analyze_top_ip_addresses(df)
    continent_counts = analyze_by_continent(df)
    time_of_day = analyze_time_of_day(df)
    risk_levels = analyze_risk_levels(df)
    weekday_trends = analyze_weekday_trends(df)

# print results to console for quick review
    print(country_counts.head(10))
    print(avg_scores.head(10))
    print(monthly_trends)
    print(top_ips)
    print(continent_counts)
    print(time_of_day)
    print(risk_levels)
    print(weekday_trends)

# generate and save visualizations for key analyses
    plot_bar(country_counts.head(10), "Top 10 Countries by Suspicious IPs", "top_countries")
    plot_bar(avg_scores.head(10), "Average Abuse Confidence Score per Country", "avg_scores")
    plot_line(monthly_trends, "Monthly Malicious Activity Trends", "monthly_trends")

    plot_bar(continent_counts, "Suspicious IPs by Continent", "continent_counts")
    plot_bar(time_of_day, "Attack Distribution by Time of Day", "time_of_day")
    plot_bar(risk_levels, "Risk Level Distribution", "risk_levels")
    plot_bar(weekday_trends, "Weekday Attack Trends", "weekday_trends")