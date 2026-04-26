// src/components/ThreatScoreChart.js
import React from "react";
import {
  Chart as ChartJS,
  ArcElement, Tooltip, Legend,
  CategoryScale, LinearScale, BarElement, Title,
} from "chart.js";
import { Doughnut, Bar } from "react-chartjs-2";

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, Title);

export default function ThreatScoreChart({ type, labels, data, colors }) {
  const chartData = {
    labels,
    datasets: [{
      data,
      backgroundColor: colors,
      borderColor:      colors.map(c => c + "cc"),
      borderWidth: 1,
      borderRadius: type === "bar" ? 6 : 0,
    }],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: true,
    plugins: {
      legend: {
        position: "bottom",
        labels: { color: "#94a3b8", font: { size: 12 }, padding: 16 },
      },
      tooltip: {
        callbacks: {
          label: (ctx) => ` ${ctx.label}: ${ctx.raw}`,
        },
      },
    },
    ...(type === "bar" && {
      scales: {
        x: { ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" } },
        y: { ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" }, min: 0, max: 100 },
      },
    }),
  };

  return type === "doughnut"
    ? <Doughnut data={chartData} options={options} />
    : <Bar     data={chartData} options={options} />;
}
