import { createCanvas } from 'canvas';
import { Chart } from 'chart.js/auto';
import fs from 'fs';
import path from 'path';

// Read the benchmark data
const rawData = fs.readFileSync('benchmark/results.json', 'utf-8');
const benchmarkData = JSON.parse(rawData);

// Extract data for the chart
const lengths = benchmarkData.map((entry: any) => entry.length);
const sizes = benchmarkData.map((entry: any) => entry.size);
const estimatedSize = benchmarkData.map((entry: any) => entry.estimatedSize);
const times = benchmarkData.map((entry: any) => entry.time);

const width = 800;
const height = 600;
const canvas = createCanvas(width, height);
const ctx = canvas.getContext('2d') as unknown as CanvasRenderingContext2D;

new Chart<'line'>(ctx, {
  type: 'line',
  data: {
    labels: lengths,
    datasets: [
      {
        label: 'Size (KB)',
        data: sizes,
        backgroundColor: 'rgba(75, 192, 192, 0.5)',
      },
      {
        label: 'Estimaed size (KB)',
        data: estimatedSize,
        backgroundColor: 'rgba(230, 220, 20, 0.5)',
      },
      {
        label: 'Total Time (MS)',
        data: times,
        backgroundColor: 'rgba(255, 99, 132, 0.5)',
      },
    ],
  },
  options: {
    scales: {
      x: {
        title: {
          display: true,
          text: 'Amount of Entries',
        },
        ticks: {
          callback: function (value) {
            return lengths[value].toLocaleString();
          },
        },
      },
    },
  },
});

const buffer = canvas.toBuffer('image/png');
const outputPath = path.resolve('benchmark/chart.png');
fs.writeFileSync(outputPath, buffer);
console.log(`Chart saved to ${outputPath}`);
