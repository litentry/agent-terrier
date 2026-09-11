import { createFileRoute } from '@tanstack/react-router';
import { DisplayApp } from '../components/DisplayApp';

export const Route = createFileRoute('/')({ component: DisplayApp });
