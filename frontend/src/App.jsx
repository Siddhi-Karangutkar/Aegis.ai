import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import LandingPage from './pages/LandingPage';
import AwarenessHub from './pages/AwarenessHub';
import CaseStudies from './pages/CaseStudies';
import InteractiveQuiz from './pages/InteractiveQuiz';
import Statistics from './pages/Statistics';
import IndicatorsGuide from './pages/IndicatorsGuide';
import UrlSafety from './pages/UrlSafety';
import BestPractices from './pages/BestPractices';
import ThreatBlog from './pages/ThreatBlog';
import BlogPost from './pages/BlogPost';
import Technology from './pages/Technology';
import ReportPhishing from './pages/ReportPhishing';
import InstallExtension from './pages/InstallExtension';
import BackgroundParticles from './components/BackgroundParticles';

function App() {
  return (
    <BrowserRouter>
      <div className="App">
        {/* Global persistent components */}
        <BackgroundParticles />
        
        {/* Route Definitions */}
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/awareness" element={<AwarenessHub />} />
          <Route path="/cases" element={<CaseStudies />} />
          <Route path="/quiz" element={<InteractiveQuiz />} />
          <Route path="/stats" element={<Statistics />} />
          <Route path="/indicators" element={<IndicatorsGuide />} />
          <Route path="/urlsafety" element={<UrlSafety />} />
          <Route path="/bestpractices" element={<BestPractices />} />
          <Route path="/blog" element={<ThreatBlog />} />
          <Route path="/blog/:id" element={<BlogPost />} />
          <Route path="/technology" element={<Technology />} />
          <Route path="/report" element={<ReportPhishing />} />
          <Route path="/install" element={<InstallExtension />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
